# Spring Framework Vulnerability Mutation/Variation Taxonomy

A comprehensive, generalized taxonomy of attack vectors, vulnerability classes, and exploitation techniques targeting applications built on the Spring Framework ecosystem (Spring Core, Spring Boot, Spring Security, Spring Cloud, Spring Data, Spring WebFlux).

---

## Classification Structure

This taxonomy organizes the Spring attack surface along three orthogonal axes:

**Axis 1 — Attack Surface (Structural Target):** The specific Spring component, mechanism, or architectural layer being targeted. This is the primary organizational axis, defining the 11 top-level categories (§1–§11) of the document. Each category represents a distinct structural aspect of the Spring ecosystem that can be mutated or abused.

**Axis 2 — Exploitation Mechanism (How the Attack Works):** The cross-cutting technique or principle that enables the attack. Multiple categories may share the same exploitation mechanism. These mechanisms are:

| Mechanism Code | Name | Description |
|---|---|---|
| **M1** | Expression Evaluation Abuse | Injecting or manipulating expression language (SpEL, OGNL) that gets evaluated by the framework |
| **M2** | Parser Differential / Normalization Mismatch | Exploiting differences in how two components (proxy/app, WAF/app, Security/MVC) parse or normalize the same input |
| **M3** | Misconfiguration Exploitation | Leveraging default, development, or insecure configurations that expose sensitive functionality |
| **M4** | Deserialization / Class Loading Abuse | Manipulating serialized data or class loading mechanisms (JNDI, gadget chains) to instantiate arbitrary objects |
| **M5** | Property Injection / Binding Abuse | Exploiting automatic data binding to modify unintended object properties |
| **M6** | State Management Flaw | Exploiting race conditions, session handling, or protocol state sequencing errors |
| **M7** | Input Validation Bypass | Circumventing filters, allowlists, or blocklists through encoding, normalization, or structural manipulation |

**Axis 3 — Impact (What Is Achieved):** The resulting effect of successful exploitation:

| Impact | Symbol |
|---|---|
| Remote Code Execution | **RCE** |
| Information Disclosure / Secret Extraction | **INFO** |
| Authorization Bypass / Privilege Escalation | **AUTHZ** |
| Server-Side Request Forgery | **SSRF** |
| Denial of Service | **DoS** |
| Account Takeover / Session Hijacking | **ATO** |
| File System Access | **FS** |

---

## §1. Expression Language Injection (SpEL)

Spring Expression Language (SpEL) is a powerful expression language integrated deeply into the Spring ecosystem. When user-controlled data enters a SpEL evaluation context without sanitization, it enables arbitrary code execution because SpEL can invoke any method accessible in the JVM.

### §1-1. Direct SpEL Injection via Input Parameters

The most fundamental form occurs when user-supplied data is directly concatenated into a SpEL expression string and evaluated.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Query annotation injection** | `@Query` or `@Aggregation` annotations in Spring Data repositories use SpEL placeholders (`?#{...}`) with unsanitized input | Spring Data MongoDB/JPA with parameterized SpEL | RCE |
| **Routing expression injection** | HTTP headers or request parameters are interpreted as SpEL routing expressions | Spring Cloud Function with `spring.cloud.function.routing-expression` header | RCE |
| **Cloud Gateway filter injection** | SpEL expressions injected through Gateway Actuator API route definitions | Spring Cloud Gateway with exposed Actuator `/gateway/routes` endpoint | RCE |
| **Error page expression injection** | Content in `${}` delimiters within error pages is parsed and executed by `ErrorMvcAutoConfiguration` | Custom error handling using Spring Boot's `resolvePlaceholder` | RCE |

**Example payload (routing expression):**
```
GET /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")
```

### §1-2. Evaluation Context Escalation

SpEL supports two evaluation contexts with vastly different security implications. Attacks target the gap between them.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **StandardEvaluationContext abuse** | Application uses `StandardEvaluationContext` (default) which allows full JVM method access | Developer fails to restrict to `SimpleEvaluationContext` | RCE |
| **Context escalation via reflection** | Bypassing `SimpleEvaluationContext` restrictions by discovering reflection utilities not on the denylist | Presence of libraries like `commons-lang3` providing alternative reflection paths | RCE |
| **Type reference bypass** | Using `T(java.lang.Runtime)` or equivalent type references to access dangerous classes | `StandardEvaluationContext` with no type restriction | RCE |

### §1-3. SpEL Filter/Denylist Bypass Techniques

When applications attempt to filter SpEL expressions, multiple bypass techniques exist.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **ASCII code construction** | Building restricted strings character-by-character using `(char)` casts: `((char)105).toString()` | Character-level denylist only | RCE |
| **Reflection chain substitution** | Replacing denylisted classes (e.g., `ReflectionUtils`) with functionally equivalent classes from transitive dependencies | Application classpath contains alternative reflection utilities | RCE |
| **String concatenation bypass** | Splitting restricted method/class names across concatenated strings to evade pattern matching | Regex-based input filtering | RCE |
| **Nested expression evaluation** | Using expression preprocessing (`__${...}__::.x`) to force evaluation before outer context checks | Thymeleaf SpEL preprocessing enabled | RCE |

---

## §2. Server-Side Template Injection (SSTI)

Spring applications commonly use Thymeleaf, FreeMarker, or Groovy templates. When user-controlled data influences template resolution or template content, it enables expression evaluation leading to RCE.

### §2-1. View Name Manipulation

The most distinctive Spring-specific SSTI vector: when a controller's return value (the view name) is influenced by user input.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Direct view name injection** | Controller returns user-controlled string as view name (e.g., `return "user/" + lang + "/welcome"`) | Controller method returns `String` without `@ResponseBody` | RCE |
| **Fragment expression injection** | User input inserted into Thymeleaf fragment expressions (e.g., `return "welcome :: " + section`) | Template fragment resolution with user input | RCE |
| **Implicit view name from URI** | Controllers with `void` or `Model` return type derive view name from request URI via `RequestToViewNameTranslator` | No explicit view name, URI-based resolution | RCE |

**Key insight:** Controllers annotated with `@ResponseBody` or `@RestController` are immune since their return values are serialized as response body, not interpreted as view names.

**Exploitation pattern:**
```
GET /path?lang=__${T(java.lang.Runtime).getRuntime().exec("calc")}__::.x
```
The `__${...}__::` wrapper exploits Thymeleaf's expression preprocessing, ensuring evaluation regardless of surrounding context.

### §2-2. Template Content Injection

When user input is embedded directly within template content rather than the view name.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Inline expression injection** | User data rendered within `[[...]]` or `[(...)]` Thymeleaf inline blocks | Thymeleaf inline mode enabled, unsanitized model attributes | RCE |
| **Attribute expression injection** | User data in `th:text`, `th:utext`, or `th:attr` attribute values without escaping | Dynamic attribute construction from user input | RCE |
| **FreeMarker built-in abuse** | Exploiting FreeMarker's `?new()` built-in to instantiate arbitrary classes | FreeMarker template engine, `TemplateClassResolver.UNRESTRICTED_RESOLVER` | RCE |

### §2-3. Modern Bypass Techniques (Spring Boot 3.x / Thymeleaf 3.1+)

Recent Thymeleaf versions have introduced denylists and restricted evaluation. Bypass research is ongoing.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Denylist class circumvention** | `org.springframework.util.ReflectionUtils` is denylisted, but alternative reflection classes from third-party libraries (e.g., `org.apache.commons.lang3`) are not | Presence of alternative reflection libraries on classpath | RCE |
| **Object chain traversal** | Using `"".getClass().forName(...)` chains to access restricted types indirectly | String literal instantiation available | RCE |
| **Preprocessing wrapper bypass** | Wrapping payloads in `__${...}__::.x` to force preprocessing before denylist evaluation | Thymeleaf expression preprocessing enabled | RCE |

---

## §3. Data Binding & Mass Assignment

Spring MVC's automatic data binding maps HTTP request parameters to Java object properties. This convenience creates a critical attack surface when binding targets have sensitive properties.

### §3-1. Direct Property Overwrite

The classic mass assignment: setting object properties the developer never intended to expose.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Role/privilege escalation** | Setting `role=ADMIN` or `isAdmin=true` via request parameter on user registration/update endpoints | Domain object has privilege-related fields without `@InitBinder` restrictions | AUTHZ |
| **Internal state manipulation** | Modifying internal bean properties like `active`, `verified`, `balance` through unprotected binding | No `setAllowedFields()` or `setDisallowedFields()` configured | AUTHZ |
| **Nested object traversal** | Accessing nested object properties via dot notation (e.g., `user.address.verified=true`) | Complex domain model with navigable object graph | AUTHZ |

### §3-2. ClassLoader Property Chain (Spring4Shell Pattern)

The landmark attack that exploited Java 9+ module system to access ClassLoader properties through Spring's data binding.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Module classLoader access** | Java 9's `class.module.classLoader` property chain bypasses pre-existing protections against `class.classLoader` | Java 9+, Spring MVC, WAR deployment on Tomcat | RCE |
| **Tomcat AccessLogValve manipulation** | Writing a JSP webshell by modifying Tomcat's logging configuration through classLoader property chain | Apache Tomcat as servlet container, WAR deployment | RCE |
| **Pipeline valve injection** | Manipulating Tomcat's request processing pipeline through classLoader → pipeline property traversal | Tomcat-specific internal class structure | RCE |

**Classic Spring4Shell payload:**
```
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

### §3-3. Binding Configuration Bypass

Techniques that circumvent developer-applied binding restrictions.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **AllowedFields bypass via alternate names** | Using alternative property path notation to access fields excluded by `setAllowedFields()` | Incomplete field name coverage in binding configuration | AUTHZ |
| **JSON body binding vs. form binding inconsistency** | `@RequestBody` JSON binding may not honor the same `@InitBinder` restrictions as form binding | Mixed content-type handling in controller | AUTHZ |
| **Nested path escape** | Traversing to parent/sibling objects through complex object graphs to reach restricted properties | Deep object graph with bidirectional references | AUTHZ |

---

## §4. Path Traversal & URL Normalization

Spring's URL routing involves multiple layers of parsing and normalization (Spring Security, Spring MVC/WebFlux, servlet container). Discrepancies between these layers create path confusion vulnerabilities.

### §4-1. Static Resource Path Traversal

Direct file system access through path traversal in static resource serving.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Double URL encoding bypass** | Encoding `../` as `%252e%252e%252f` — the first decode passes validation, the second creates the traversal | Spring WebMvc.fn or WebFlux.fn serving static resources (CVE-2024-38819) | FS |
| **Symbolic link following** | Traversing through symbolic links in the static resource directory to escape the intended root | File system with symlinks, insufficient `isInvalidPath` checks | FS |
| **Functional endpoint traversal** | Path traversal specifically in `RouterFunction`-based (WebMvc.fn/WebFlux.fn) resource handlers vs. traditional `ResourceHttpRequestHandler` | Application uses functional web framework for static resources (CVE-2024-38816) | FS |

### §4-2. Security Filter Path Mismatch

Discrepancies between how Spring Security and Spring MVC/WebFlux interpret the same URL path.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Trailing slash mismatch** | Spring Security pattern does not match URL with trailing slash that Spring MVC does route | Strict pattern matching in Security, lenient in MVC | AUTHZ |
| **Dot segment normalization difference** | `/admin/./secret` normalized differently by Security filter vs. MVC dispatcher | Un-normalized URL comparison in security filter chain | AUTHZ |
| **Case sensitivity discrepancy** | URL path case handled differently between Security patterns and MVC handler mappings on case-insensitive filesystems | Windows deployment or case-insensitive URL matching | AUTHZ |
| **Semicolon/path parameter stripping** | Spring MVC strips `;` path parameters before routing but Security evaluates the full URL | Servlet container preserving path parameters | AUTHZ |
| **Un-normalized URL in WebFlux** | WebFlux Security not normalizing URLs before authorization evaluation | Spring WebFlux without `StrictServerWebExchangeFirewall` (CVE-2024-38821) | AUTHZ |

### §4-3. WAF/Proxy Path Confusion

The path seen by a WAF or reverse proxy differs from what Spring MVC ultimately routes to.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Double encoding differential** | WAF decodes once (passes), Spring decodes twice (traversal resolves) | WAF in front of Spring application with multi-stage decoding | FS, AUTHZ |
| **Path parameter injection** | URL like `/admin;bypass=1/secret` — WAF sees full path, Spring strips `;bypass=1` | Reverse proxy or WAF not aware of servlet path parameter semantics | AUTHZ |
| **Null byte injection (legacy)** | `%00` terminates path string in native handlers but not in Java string processing | Older servlet containers or native file system APIs | FS |

---

## §5. Actuator & Management Endpoint Exposure

Spring Boot Actuator provides operational endpoints for monitoring, metrics, and management. When exposed without authentication, these endpoints become a comprehensive attack surface.

### §5-1. Information Disclosure Endpoints

Endpoints that directly leak sensitive data.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Heap dump extraction** | `/actuator/heapdump` captures the full JVM heap containing credentials, tokens, API keys, database passwords loaded in memory | Heapdump endpoint exposed without authentication (~2.3% of cloud deployments) | INFO |
| **Environment properties exposure** | `/actuator/env` reveals all configuration properties including database credentials, cloud keys, third-party API tokens | Env endpoint exposed (~4% of cloud deployments) | INFO |
| **Config properties dump** | `/actuator/configprops` lists all `@ConfigurationProperties` beans with their values | Configprops endpoint exposed | INFO |
| **Thread dump analysis** | `/actuator/threaddump` reveals stack traces, potentially exposing internal logic, database queries, and timing information | Threaddump endpoint exposed | INFO |
| **Mapped endpoints enumeration** | `/actuator/mappings` reveals all request mappings including hidden/internal APIs | Mappings endpoint exposed | INFO |
| **Spring Beans enumeration** | `/actuator/beans` reveals all Spring beans, their types, scopes, and dependencies | Beans endpoint exposed | INFO |

### §5-2. Remote Code Execution via Actuator Chains

Multi-step attacks that chain Actuator endpoints to achieve RCE.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Jolokia JNDI injection** | `/actuator/jolokia` exposes MBeans; the `reloadByURL` action in Logback can load external XML configurations containing JNDI lookups | Jolokia library on classpath, Logback as logging framework | RCE |
| **H2 database console JNDI** | Chain: `/actuator/env` sets `spring.datasource.url` to JNDI URL → `/actuator/restart` triggers connection with attacker-controlled JNDI | H2 database on classpath, env + restart endpoints exposed | RCE |
| **SnakeYAML deserialization** | Chain: `/actuator/env` sets `spring.cloud.bootstrap.location` to malicious YAML URL → `/actuator/refresh` triggers SnakeYAML deserialization | Spring Cloud + SnakeYAML < 2.0, env + refresh endpoints exposed | RCE |
| **Eureka XStream deserialization** | Chain: `/actuator/env` sets `eureka.client.serviceUrl.defaultZone` to malicious server → `/actuator/refresh` triggers XStream deserialization | Spring Cloud Netflix Eureka client on classpath | RCE |
| **Logback JNDI via Jolokia** | Jolokia endpoint triggers Logback's `JMXConfigurator` to reload logging config from external URL containing JNDI references | Jolokia + Logback, JNDI not restricted | RCE |

### §5-3. Actuator Path Discovery & Bypass

Techniques to locate Actuator endpoints when they're not at default paths.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Custom base path brute force** | Actuator endpoints moved to non-default base path (e.g., `/management/`, `/admin/monitor/`) but still accessible | `management.endpoints.web.base-path` changed but not firewalled | varies |
| **Separate management port exposure** | Actuator bound to separate port (e.g., 8081) accessible from different network zone | `management.server.port` configured, network segmentation failure | varies |
| **Partial endpoint enablement** | Developers disable `info` and `health` but forget to disable `env`, `heapdump`, or `jolokia` | Incomplete `management.endpoints.web.exposure.include` configuration | varies |

---

## §6. Deserialization & Object Injection

Spring applications handle serialized data through multiple channels. Unsafe deserialization enables arbitrary object instantiation and code execution.

### §6-1. Java Native Deserialization

Traditional `ObjectInputStream`-based deserialization attacks.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Spring remoting deserialization** | `HttpInvokerServiceExporter` and `RmiServiceExporter` deserialize incoming requests without type filtering | Legacy Spring Remoting endpoints exposed | RCE |
| **JMS message deserialization** | Spring JMS listeners consuming `ObjectMessage` types deserialize arbitrary payloads | JMS message broker accepting untrusted messages | RCE |
| **Spring Session Redis deserialization** | Spring Data Redis uses Java native serialization by default; poisoned Redis data triggers deserialization on retrieval | Redis accessible to attacker, default serializer | RCE |
| **View state deserialization** | Spring Web Flow or Spring Faces storing serialized view state in hidden form fields | Client-side view state without encryption/signing | RCE |

### §6-2. Library-Specific Deserialization

Deserialization through third-party libraries commonly found in Spring applications.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Jackson polymorphic deserialization** | `@JsonTypeInfo` with `Id.CLASS` or `Id.MINIMAL_CLASS` enables arbitrary type instantiation from JSON | Jackson with polymorphic type handling enabled, gadget class on classpath | RCE |
| **SnakeYAML Constructor abuse** | `yaml.load()` with default `Constructor` instantiates arbitrary Java classes from YAML type tags | SnakeYAML < 2.0, Spring Cloud Config importing YAML | RCE |
| **XStream deserialization** | XStream's default configuration allows arbitrary type instantiation from XML | XStream without explicit type permissions, Spring Cloud Netflix | RCE |
| **Kryo deserialization** | Kryo serialization without class registration requirement allows arbitrary type instantiation | Spring applications using Kryo for caching/messaging | RCE |

### §6-3. JNDI Injection

Java Naming and Directory Interface lookups triggered with attacker-controlled input.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **H2 JDBC URL JNDI** | H2 database connection string supports JNDI lookups: `jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://...'` | H2 console or database endpoint accessible | RCE |
| **DataSource JNDI** | Setting `spring.datasource.jndi-name` or `spring.datasource.url` to JNDI lookup URL via Actuator env manipulation | Actuator env + restart exposed, JNDI not restricted | RCE |
| **Log4j/Logback JNDI** | Triggering JNDI lookup through logging framework configuration reload | Log4j2 < 2.17.0 or Logback with JNDI appender, configuration reload capability | RCE |

---

## §7. Authentication & Authorization Bypass

Spring Security provides a comprehensive security framework, but its complexity creates multiple vectors for bypass.

### §7-1. URL Pattern Matching Bypass

Exploiting inconsistencies in how Spring Security matches URL patterns against incoming requests.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **RegexRequestMatcher dot bypass** | `.` in regex patterns matches newline on some servlet containers, allowing bypass with URL-encoded newlines | `RegexRequestMatcher` with `.` in pattern (CVE-2022-22978) | AUTHZ |
| **Double-wildcard prefix mismatch** | Un-prefixed `**` pattern in WebFlux Security configuration doesn't match as expected, creating gaps | Spring Security WebFlux with `**` pattern without leading `/` (CVE-2023-34034) | AUTHZ |
| **Space trimming inconsistency** | Spring MVC trims spaces in path segments but Spring Security doesn't, allowing bypass with `/ admin/` | Path matching strictness difference (CVE-2016-5007) | AUTHZ |
| **Generic type annotation detection flaw** | Method-level security annotations (`@PreAuthorize`, `@Secured`) on generic superclass/interface methods not properly detected | Parameterized types or unbounded generic superclasses (CVE-2025-41248, CVE-2025-41249) | AUTHZ |

### §7-2. Dispatch Type Bypass

Exploiting Spring Security's handling of different servlet dispatch types.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **FORWARD dispatch bypass** | Security rules not applied to internally forwarded requests | `AuthorizationFilter` without FORWARD dispatch type coverage (CVE-2022-31692) | AUTHZ |
| **INCLUDE dispatch bypass** | Security rules not applied to included request content | `AuthorizationFilter` configuration gap for INCLUDE dispatch | AUTHZ |
| **Error dispatch bypass** | Security rules not applied to error page rendering, allowing access to protected data via error responses | Error handler returning sensitive data without separate authorization | AUTHZ |

### §7-3. Method-Level Security Bypass

Circumventing `@PreAuthorize`, `@PostAuthorize`, `@Secured`, and `@RolesAllowed` annotations.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Proxy-based AOP bypass** | Self-invocation within the same bean bypasses Spring's proxy-based security interceptors | Method calling secured method on `this` instead of through proxy | AUTHZ |
| **Interface-implementation mismatch** | Security annotation on interface method not inherited by implementation class in certain proxy modes | CGLIB proxy mode with annotations on interfaces | AUTHZ |
| **SpEL injection in @PreAuthorize** | User-controlled data reaching SpEL expressions in `@PreAuthorize` annotations | Dynamic SpEL expression construction from request data | RCE |

---

## §8. Protocol & Connection Layer Attacks

Vulnerabilities in Spring's handling of HTTP, WebSocket, and other protocol-level concerns.

### §8-1. HTTP Request Smuggling

Discrepancies between how a front-end proxy and the Spring application parse HTTP request boundaries.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **CL-TE / TE-CL framing mismatch** | Front-end and back-end disagree on Content-Length vs. Transfer-Encoding precedence | Spring Cloud Gateway or reverse proxy in front of Spring application | AUTHZ, ATO |
| **Gateway route injection** | Injecting additional routes through request smuggling to bypass gateway-level access controls | Spring Cloud Gateway with request smuggling vulnerability (CVE-2021-22051) | AUTHZ |

### §8-2. WebSocket / STOMP Attacks

Vulnerabilities in Spring's WebSocket and STOMP protocol handling.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **STOMP frame ordering bypass** | Sending SEND/SUBSCRIBE frames before CONNECT frame is authenticated by embedding multiple STOMP frames in a single WebSocket message | Spring WebSocket with STOMP sub-protocol (CVE-2025-41254) | AUTHZ |
| **WebSocket CSRF** | WebSocket connections don't carry CSRF tokens by default; cross-origin WebSocket handshake may succeed | CORS not restricted for WebSocket upgrade endpoint | ATO |
| **SockJS fallback exploitation** | SockJS HTTP fallback transports (XHR, JSONP, iframe) may bypass WebSocket-specific security controls | SockJS enabled with HTTP fallback transports | AUTHZ |

### §8-3. HTTP Parameter Handling

Attacks exploiting Spring's HTTP parameter parsing behavior.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **HTTP Parameter Pollution** | Submitting duplicate parameter names; Tomcat uses first occurrence, other containers may differ | Spring behind reverse proxy with different parameter precedence | AUTHZ |
| **Content-Type confusion** | Sending JSON body with `application/x-www-form-urlencoded` Content-Type or vice versa to bypass type-specific validation | Inconsistent content-type handling in controller | AUTHZ |

---

## §9. XML & Data Processing Injection

Attacks targeting Spring's XML parsing, data query, and external data processing capabilities.

### §9-1. XML External Entity (XXE) Injection

Exploiting XML parsers in Spring components that process external entities.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Spring Integration XML XXE** | `spring-integration-xml` processes XML from untrusted sources with external entities enabled | Spring Integration XML support without hardened parser (CVE-2019-3772) | FS, SSRF |
| **Spring Web Services XXE** | `spring-ws-core` and `spring-xml` fail to restrict external entity processing | Spring Web Services with default XML parser configuration (CVE-2019-3773) | FS, SSRF |
| **Spring Batch XXE** | `spring-batch-core` XML job configuration processing allows external entities | Spring Batch processing untrusted XML job definitions (CVE-2019-3774) | FS, SSRF |
| **Jolokia XXE** | Jolokia Actuator endpoint processes XML requests without disabling external entities | Jolokia on classpath with XML content type support | FS, SSRF |
| **Custom XML parser misconfiguration** | Application-level XML parsing using `DocumentBuilderFactory`, `SAXParserFactory`, or `XMLInputFactory` without disabling external entities | Any Spring application processing user-supplied XML | FS, SSRF |

### §9-2. Spring Data Query Injection

Injection attacks through Spring Data's query abstraction layers.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **SpEL in @Query annotations** | SpEL expressions in `@Query` value with `?#{...}` parameter placeholders accepting unsanitized input | Spring Data MongoDB/JPA with SpEL-containing queries (CVE-2022-22980) | RCE |
| **JPQL/HQL injection** | Native or JPQL queries constructed with string concatenation instead of parameterized queries | Spring Data JPA with dynamic query construction | INFO, AUTHZ |
| **MongoDB NoSQL injection** | JSON/BSON operator injection through Spring Data MongoDB query parameters | Direct JSON query construction from user input | INFO, AUTHZ |
| **LDAP injection** | LDAP filter injection through Spring LDAP query construction | Spring LDAP with string-based filter construction | AUTHZ |

---

## §10. OAuth2 / OpenID Connect & Session Security

Vulnerabilities in Spring Security's OAuth2 client, resource server, and authorization server implementations.

### §10-1. OAuth2 Flow Manipulation

Attacks targeting the OAuth2 authorization flow.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Open redirect via redirect_uri** | Spring's `DefaultRedirectResolver` allows subdomain matching by default, enabling token theft via subdomain takeover | Default redirect URI validation, exploitable subdomain | ATO |
| **State parameter CSRF** | Missing or predictable `state` parameter allows cross-site request forgery in OAuth2 flow | Custom OAuth2 implementation without proper state validation | ATO |
| **Authorization code interception** | Lack of PKCE allows authorization code interception on public clients | OAuth2 public client without PKCE enforcement | ATO |
| **Token leakage via referrer** | Access tokens in URL fragments leaked through `Referer` header to third-party resources | Implicit grant flow, external resource loading on callback page | ATO |

### §10-2. JWT / Token Vulnerabilities

Attacks on token validation and processing.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Algorithm confusion** | Switching JWT signing algorithm from RS256 to HS256, using public key as HMAC secret | Resource server accepting multiple algorithms without strict validation | AUTHZ |
| **JWK URL injection** | Manipulating `jku` (JWK Set URL) header to point to attacker-controlled key server | Resource server following `jku` header without allowlist | AUTHZ |
| **Token scope escalation** | Modifying token scope/claims when token validation only checks signature, not content constraints | Insufficient claim validation beyond signature verification | AUTHZ |
| **Refresh token theft** | Extracting refresh tokens from Actuator heapdump, logs, or error responses | Refresh tokens stored in memory, verbose logging | ATO |

### §10-3. Session Management Flaws

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Session fixation** | Session ID not regenerated after authentication, allowing pre-authentication session planting | Custom authentication flow bypassing Spring Security's default session management | ATO |
| **Concurrent session bypass** | Multiple simultaneous authentication requests bypass maximum session count enforcement | Race condition in session registry (§8 M6 cross-reference) | AUTHZ |
| **Session serialization attacks** | Spring Session data stored in Redis/JDBC using Java serialization, enabling deserialization attacks (§6-1 cross-reference) | External session store with Java native serialization | RCE |

---

## §11. File Upload & Resource Handling

Attacks exploiting Spring's multipart file handling and resource serving mechanisms.

### §11-1. Malicious File Upload

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Filename path traversal** | Original filename containing `../` sequences used directly in file storage path | `MultipartFile.getOriginalFilename()` used without sanitization | FS, RCE |
| **Content-Type bypass** | Server validates file extension but not actual content, allowing upload of JSP/executable files with allowed extensions | Extension-only validation without magic byte checking | RCE |
| **Multipart parser differential** | Differences between Apache Commons FileUpload and Spring's standard multipart resolver in boundary parsing | Multiple multipart parsers in the request processing chain | M7 |
| **Unrestricted file size DoS** | Missing or misconfigured `spring.servlet.multipart.max-file-size` / `max-request-size` | Default or removed size limits | DoS |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Cloud Metadata SSRF** | Spring app on AWS/GCP/Azure with SSRF via XXE (§9-1) or Actuator SSRF | §5 + §9 |
| **WAF Bypass to RCE** | WAF → Reverse Proxy → Spring with path confusion + SpEL | §1 + §4-3 |
| **Internal API Access** | Spring Cloud Gateway + request smuggling to access internal microservices | §8-1 + §4-2 |
| **Supply Chain via Dependencies** | Vulnerable transitive dependencies (SnakeYAML, XStream, Log4j) exploited through Actuator chains | §5-2 + §6-2 |
| **Development-to-Production Leak** | H2 console, debug endpoints, Actuator exposed in production | §5 + §6-3 |
| **Multi-Tenant Privilege Escalation** | Mass assignment + authorization bypass in shared Spring application | §3 + §7 |
| **CI/CD Pipeline Compromise** | Exposed Actuator env endpoint used to extract secrets for lateral movement | §5-1 |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Year | Impact |
|---------------------|-----------|------|--------|
| §3-2 (ClassLoader chain) | CVE-2022-22965 (Spring4Shell) | 2022 | Critical RCE via mass assignment on Java 9+ |
| §1-1 (Routing SpEL) | CVE-2022-22963 | 2022 | Critical RCE via Spring Cloud Function routing header |
| §1-1 (Gateway SpEL) | CVE-2022-22947 | 2022 | Critical RCE via Spring Cloud Gateway Actuator |
| §9-2 (MongoDB SpEL) | CVE-2022-22980 | 2022 | Critical RCE via SpEL in Spring Data MongoDB @Query |
| §7-1 (Regex bypass) | CVE-2022-22978 | 2022 | Authorization bypass via RegexRequestMatcher |
| §7-2 (Dispatch bypass) | CVE-2022-31692 | 2022 | Authorization bypass via FORWARD/INCLUDE dispatch |
| §7-1 (Wildcard mismatch) | CVE-2023-34034 | 2023 | Authorization bypass in WebFlux via un-prefixed `**` |
| §4-1 (Double encoding) | CVE-2024-38816 | 2024 | Path traversal in functional web frameworks |
| §4-1 (Double encoding) | CVE-2024-38819 | 2024 | Path traversal in WebMvc.fn/WebFlux.fn static resources |
| §4-2 (Un-normalized URL) | CVE-2024-38821 | 2024 | WebFlux static resource authorization bypass |
| §6-2 (Package upload) | CVE-2024-37084 | 2024 | RCE via arbitrary package upload/deployment in Spring Cloud Data Flow Skipper server |
| §7-1 (Annotation detection) | CVE-2025-41248 | 2025 | Authorization bypass via generic type annotation detection |
| §7-1 (Annotation detection) | CVE-2025-41249 | 2025 | Authorization bypass in Spring Framework method security |
| §8-2 (STOMP ordering) | CVE-2025-41254 | 2025 | STOMP frame ordering bypass for unauthorized messages |
| §1-1 (Gateway SpEL) | CVE-2025-41243 | 2025 | Spring Cloud Gateway environment attribute SpEL evaluation |
| §6-3 (H2 JNDI) | CVE-2021-42392 | 2022 | RCE via JNDI lookup in H2 Database Console |
| §8-1 (Gateway smuggling) | CVE-2021-22051 | 2021 | HTTP request smuggling in Spring Cloud Gateway |
| §9-1 (Spring WS XXE) | CVE-2019-3773 | 2019 | XXE in Spring Web Services |
| §9-1 (Integration XXE) | CVE-2019-3772 | 2019 | XXE in Spring Integration XML |
| §5-1 (Heapdump) | HackerOne #1019367 | 2020 | Memory dump and env disclosure via exposed Actuator |
| §5-1 (Env disclosure) | HackerOne #862589 | 2020 | Spring Actuator endpoints exposing secrets |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SpringBoot-Scan** | Full Spring Boot attack surface | Actuator discovery, sensitive file detection, CVE exploit verification (supports CVE-2025-41243) |
| **SBSCAN** | Spring Boot vulnerability scanning | Sensitive information scanning + Spring-specific CVE verification |
| **Spring Boot Dump Scanner** (Burp Extension) | Actuator heapdump/threaddump | Automatic detection of exposed dump endpoints and secret extraction |
| **Spring-Boot-Actuator-Exploit** | Jolokia XXE/RCE chain | Jolokia MBean exploitation and Logback JNDI injection |
| **spring-boot-actuator-h2-rce** | H2 + Actuator chain | Env manipulation → H2 database alias → RCE |
| **ysoserial** | Java deserialization | Gadget chain generation for multiple Java libraries |
| **SpringBootExploit Toolkit** | Comprehensive Spring Boot | SnakeYAML RCE, Eureka XStream, Jolokia JNDI PoCs |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **local-spring-vuln-scanner** | JAR/WAR file analysis | Scans archives for known vulnerable Spring class files |
| **Snyk / Dependabot** | Dependency vulnerability | SCA scanning for vulnerable Spring transitive dependencies |
| **Spring Boot Actuator Security Configuration** | Actuator hardening | `management.endpoints.web.exposure.include` restriction, authentication enforcement |
| **StrictServerWebExchangeFirewall** | WebFlux URL normalization | Normalizes URLs before security evaluation in WebFlux applications |

### Research / Fuzzing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **CodeQL** (SpEL query) | SpEL injection detection | Static analysis detecting SpEL expression evaluation with tainted input |
| **Semgrep** (Spring rules) | Multiple vulnerability classes | Pattern-based static analysis for Spring-specific vulnerability patterns |
| **Contrast Security** | Runtime protection | RASP-based blocking of Spring View Manipulation and SpEL injection at runtime |

---

## Summary: Core Principles

### Why the Spring Ecosystem Is a Rich Attack Surface

The Spring Framework's fundamental design philosophy — **"convention over configuration" with extensive automatic behavior** — is simultaneously its greatest productivity advantage and its deepest security liability. Auto-binding of HTTP parameters to Java objects (§3), automatic expression evaluation in templates (§2) and queries (§9-2), runtime bean configuration through Actuator endpoints (§5), and automatic exposure of management functionality all create implicit trust relationships between external input and internal execution.

### Why Incremental Patches Fail

The Spring vulnerability space resists incremental patching for three structural reasons:

1. **Layered parsing creates combinatorial bypass potential.** Every additional component in the request processing chain (WAF → reverse proxy → Spring Security → Spring MVC → template engine) adds a normalization step, and every pair of adjacent components can produce a parser differential (§4). Patching one normalization step often leaves another exploitable.

2. **The classpath is the attack surface.** Many of the most severe Spring vulnerabilities (§5-2, §6-2) are not in Spring itself but in libraries on the classpath — SnakeYAML, XStream, Jackson, H2, Logback, Jolokia. Spring's auto-configuration philosophy means that the mere presence of a library on the classpath activates functionality, and that functionality becomes an attack vector. The Spring application's true attack surface is the transitive closure of its entire dependency tree.

3. **Expression languages are Turing-complete by design.** SpEL (§1) and Thymeleaf expressions (§2) are intentionally powerful — they can access any class, invoke any method, and traverse any object graph. Security is bolted on through denylists of dangerous classes, but the set of "dangerous" classes grows with every library added to the classpath. This is a losing arms race.

### Structural Solution Direction

The fundamental mitigation requires moving from **denylist-based security** (blocking known-bad) to **allowlist-based security** (permitting known-good):

- Use `SimpleEvaluationContext` instead of `StandardEvaluationContext` for all SpEL evaluation with external input (§1)
- Enforce `@ResponseBody` / `@RestController` as default to prevent view name manipulation (§2)
- Use explicit `@InitBinder` with `setAllowedFields()` for every binding target (§3)
- Deploy `StrictServerWebExchangeFirewall` and normalize all paths before security evaluation (§4)
- Default-deny all Actuator endpoints and explicitly enable only what is needed (§5)
- Replace Java native serialization with type-safe alternatives (Jackson, Protobuf) everywhere (§6)
- Prefer `AntPathRequestMatcher` with exact patterns over regex matchers; avoid wildcard patterns (§7)
- Disable external entity processing in all XML parsers (§9)
- Use `ExactMatchRedirectResolver` for OAuth2 redirect URIs (§10)

---

## Reference

### Sources Consulted

- Spring Framework Official Security Advisories (spring.io/security)
- National Vulnerability Database (nvd.nist.gov) — CVE records 2019–2025
- OWASP Top 10 (2021, 2025 editions)
- HackerOne Bug Bounty Reports (publicly disclosed Spring-related reports)
- Application Security Cheat Sheet (0xn3va.gitbook.io/cheat-sheets/framework/spring)
- PortSwigger Research — SSTI, OAuth, HTTP Smuggling
- Veracode Research — Spring View Manipulation, Actuator exploitation
- Wiz Cloud Security Research — Spring Boot Actuator Misconfigurations (2024)
- JFrog Security Research — H2 JNDI, Spring WebFlux CVE-2023-34034
- HackTricks — Spring Actuators reference
- Snyk Vulnerability Database — Spring ecosystem CVEs
- modzero Research — SSTI in Modern Spring Boot 3.3.4 (2024)
- Acunetix Research — Thymeleaf SSTI exploitation
- SonicWall Threat Intelligence — CVE-2024-37084 analysis
- Various HeroDevs, SentinelOne, Miggo vulnerability advisories (2024–2025)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
