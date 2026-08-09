# Type Confusion and Coercion — Mutation/Variation Taxonomy

> Vulnerability patterns arising from type misinterpretation, implicit conversion, and type-system boundary violations.

---
## Classification Structure

Type confusion and coercion vulnerabilities share a single root cause: **a value is interpreted as a type different from its actual type**, and this misinterpretation creates security-relevant behavioral divergence. This class is uniquely cross-cutting — it manifests in native memory (C/C++), JIT compilers (V8/JSC/SpiderMonkey), scripting language operators (PHP/JS/Python), serialization formats (JSON/Pickle/YAML/Protobuf), databases (SQL/NoSQL), and API boundaries (GraphQL/gRPC).

The taxonomy is organized along three axes:

**Axis 1 — Mutation Target (Primary):** The structural component where type confusion or coercion occurs. This axis defines the main body of the document (§1–§10).

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the type mismatch that creates the vulnerability. Every technique in the taxonomy exhibits one or more of these discrepancy types:

| Discrepancy Type | Mechanism | Example |
|---|---|---|
| **Implicit Equivalence** | Two semantically distinct types are treated as equal by language coercion rules | PHP `"0e123" == "0e456"` → both coerced to float `0` |
| **Speculative Narrowing** | Compiler/optimizer assumes a narrower type than the actual runtime value | JIT eliminates bounds check after incorrectly proving array index is non-negative |
| **Guard Elimination** | A type check is removed as "redundant" by an optimization pass | Turbofan removes CheckMaps node after type feedback suggests single type |
| **Schema-Wire Mismatch** | Declared schema type differs from actual wire encoding or delivered payload | Protobuf field declared `int32` but sender encodes as `string` wire type |
| **Boundary Erasure** | Type information is lost when data crosses a language, runtime, or system boundary | JVM generic type erasure makes `List<String>` and `List<Int>` indistinguishable at runtime |
| **Semantic Reinterpretation** | Same raw bytes/bits are interpreted as a fundamentally different type | C++ `reinterpret_cast` treats object memory as a different class, accessing wrong vtable |

**Axis 3 — Attack Scenario (Mapping):** The architectural context in which the type confusion is weaponized. Defined in the Attack Scenario Mapping section.

---

## §1. Memory Layout and Object Representation

Type confusion at the memory level occurs when a program accesses an object through a pointer or reference typed to a different class, struct, or union member than the object's actual type. This is the oldest and most severe form — it produces direct arbitrary read/write primitives from a single bug.

### §1-1. C++ Bad-Casting (static_cast / reinterpret_cast)

Unsafe downcasting between related or unrelated C++ types without runtime verification causes field offset misalignment. When an object of type A is accessed through a pointer typed as B, field reads and writes hit incorrect offsets, and virtual method calls dispatch through the wrong vtable.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Downcast Without RTTI Check** | `static_cast<Derived*>(base_ptr)` when the actual object is a different derived type; field offsets diverge between sibling classes | RTTI disabled (`-fno-rtti`) or `dynamic_cast` avoided for performance |
| **reinterpret_cast Across Hierarchies** | Treats raw memory of one class as another unrelated class; all field accesses read wrong offsets | Cast between types with no inheritance relationship |
| **C-Style Cast in C++ Code** | `(DerivedType*)ptr` silently performs `static_cast` or `reinterpret_cast` depending on context; programmer may not realize which one applies | Mixed C/C++ codebase; compiler chooses cast semantics implicitly |
| **Multiple Inheritance Diamond Offset** | In diamond inheritance, casting between sibling paths adjusts `this` pointer differently; incorrect cast path yields shifted field access | Complex class hierarchies with virtual base classes |

### §1-2. Virtual Table (vtable) Corruption

Objects in C++ store a hidden vtable pointer as their first field (implementation-dependent). Type confusion that overlaps one object's vtable pointer with another's data fields allows an attacker to redirect virtual method dispatch to arbitrary code.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **UAF-to-Type-Confusion** | A freed object's memory is reallocated for a different type; the old dangling pointer now accesses the new type's layout through the old type's interface | Heap allocator reuses memory for a differently-typed allocation |
| **Heap Spray Type Substitution** | Attacker fills freed memory with controlled data shaped like a valid vtable; dangling pointer dereferences the fake vtable | Predictable heap layout; attacker can allocate controlled objects |
| **Credential/Object Swap** | Kernel object slot is freed and reallocated with a differently-privileged object of the same size; system treats the new object as the old type (DirtyCred pattern) | Same-size slab allocation; timing window for swap |

### §1-3. Union and Tagged Union Misuse

C/C++ unions share memory among multiple fields. Reading a union member different from the one last written reinterprets the stored bytes under a different type.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Union Member Aliasing** | Writing a `float` to a union member and reading it as `uint32_t` (or vice versa) reinterprets the IEEE 754 bit pattern | No tag field tracking which member is active; C permits this, C++ has restrictions |
| **Tagged Union Tag Corruption** | Discriminant/tag value is corrupted (via overflow, OOB write, or deserialization) to reference a variant that doesn't match the stored data | Tag value not bounds-checked; deserialization trusts external tag |
| **Rust Enum Discriminant Corruption** | Zero-copy deserialization crates (e.g., rkyv) interpret byte buffers directly as Rust enums; crafted archives set discriminant values to "impossible" states, breaking niche optimization assumptions | `unsafe` deserialization without discriminant validation |

### §1-4. void* and Opaque Pointer Casting

C code pervasively uses `void*` for generic programming. Every cast from `void*` to a concrete type is an assertion that the pointed-to memory contains that type — an assertion the compiler cannot verify.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Callback Data Pointer Confusion** | Generic callback receives `void* user_data`; callback implementation casts to wrong type | Registration and invocation use different type assumptions |
| **container_of Macro Misuse** | Linux kernel's `container_of(ptr, type, member)` computes struct base from member pointer; wrong type parameter yields incorrect base address | Kernel subsystem passes embedded struct to wrong handler |
| **Opaque Handle Type Confusion** | Opaque integer/pointer handles (file descriptors, HANDLEs, GObject pointers) passed to wrong subsystem's API | No type tag on handle; wrong API called |

---

## §2. JIT Compiler Type Speculation

Modern JavaScript engines (V8/Turbofan/Maglev, JavaScriptCore/DFG/FTL, SpiderMonkey/Warp) compile hot code paths using speculative type assumptions derived from runtime profiling. When these assumptions are wrong — either because the profiler was misled or because the compiler's reasoning is flawed — the emitted machine code accesses memory using incorrect type layouts. This is the most actively exploited type confusion frontier, with multiple in-the-wild zero-days exploited in Chrome, Safari, and Firefox in recent years.

### §2-1. Type Feedback Poisoning

JIT compilers profile value types during interpreted execution to specialize compiled code. An attacker trains the profiler with type A, triggers compilation, then passes type B to the compiled code.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Monomorphic Inline Cache Pollution** | Warmup loop passes only objects with Map/Structure X; JIT compiles specialized code assuming Map X; attacker passes object with Map Y post-compilation | JIT trusts profiler without re-checking in optimized path |
| **Polymorphic-to-Megamorphic Transition Exploit** | Attacker introduces enough distinct types to force a megamorphic (generic) path, then exploits weaker type handling in the generic fallback | Megamorphic stub has different type assumptions than specialized code |
| **Deopt-Recompile Feedback Poisoning** | Trigger deoptimization with poisoned type feedback; second compilation pass uses corrupted profile data | Two-phase optimization where second pass trusts first pass's profiling |

### §2-2. Bounds Check Elimination

JIT compilers prove array index ranges to eliminate bounds checks. If the range proof is wrong due to incorrect type reasoning, out-of-bounds memory access results.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Range Analysis Error** | Compiler proves index is within `[0, array.length)` using type-based reasoning; attacker constructs value that violates the proven range | Integer wrapping, negative zero, or NaN not handled in range analysis |
| **CheckBounds Node Elimination** | Redundancy elimination pass removes a bounds check that a prior check supposedly covers; the prior check used wrong type information | Two checks on same value but type changes between them |
| **Typed Array Length Confusion** | TypedArray's `.length` is derived from its backing buffer; detaching or neutering the buffer changes effective length after bounds check was compiled | SharedArrayBuffer or transferred buffer post-compilation |

### §2-3. Escape Analysis and Allocation Elimination

When the JIT determines an object does not escape a function, it may stack-allocate it or eliminate it entirely, replacing field accesses with register values. Type confusion in escape analysis causes the wrong memory layout model.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Stack-Allocated Object Type Confusion** | JIT stack-allocates object with layout of type A; a type B object reaches the same code path; stack frame is accessed with wrong offsets | Escape analysis succeeds but type specialization is wrong |
| **Scalar Replacement Mistyping** | Object fields replaced with scalar variables; field access compiled for type A's offset hits type B's different-offset field | Object shape changes between profiling and execution |

### §2-4. Redundant Type Guard Elimination

JIT compilers insert type guards (CheckMaps in V8, Structure checks in JSC) at function entries and property accesses. Optimization passes may eliminate guards deemed "already proven."

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Turbofan CheckMaps Elimination** | Global value numbering or load elimination proves a CheckMaps node is redundant; but the proof is invalid due to side effects between the two checks | Side-effecting operation changes object's Map between original and eliminated check |
| **DFG/FTL Structure Check Removal** | JSC's speculation mechanism removes structure checks after abstract interpretation; attacker changes object structure post-check | Abstract interpreter models incorrect type flow |
| **Warp Guard Folding** | SpiderMonkey's Warp compiler folds type guards based on CacheIR; incorrect folding removes necessary checks | CacheIR stub has overly broad type assumption |

### §2-5. WebAssembly Type Boundary Confusion

WebAssembly introduces a static type system that interacts with JavaScript's dynamic types at the boundary. Type confusion arises at module-to-module boundaries and at Wasm-JS interop.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Wasm Cross-Module Struct Type Validation** | Two Wasm modules define structurally similar types; incorrect structural equality check allows passing one module's struct to another's function expecting a different layout | Wasm GC reference types with subtyping (Chrome 119+, Firefox 120+) |
| **Wasm GC ref.cast Bypass** | Buggy `ref.cast` implementation fails to verify GC heap object's actual type; attacker passes mistyped GC struct reference | GC objects live outside linear memory sandbox |
| **JS-Wasm Externref Confusion** | JavaScript passes an externref value to Wasm that expects a specific type; Wasm code trusts the externref without type checking | No runtime type check at JS-Wasm boundary for externref |

---

## §3. Comparison and Equality Operators

Loosely-typed languages implement comparison operators that perform implicit type coercion before evaluation. The coercion rules create equivalences between values that should be semantically distinct, enabling authentication bypasses, authorization escalation, and filter evasion.

### §3-1. PHP Loose Comparison (==)

PHP's `==` operator follows a complex coercion matrix where operand types determine which coercion path is applied before comparison. This is the single most documented type coercion attack surface in web applications.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **String-to-Integer Coercion** | Non-numeric strings are coerced to integer `0`; `"admin" == 0` evaluates to `true` | PHP < 8.0; one operand is integer, other is non-numeric string |
| **Magic Hash (0e Trick)** | Hash digests matching `0e\d+` are interpreted as zero in scientific notation; two different plaintexts with magic hashes compare as equal (`0 == 0`) | Loose comparison of MD5/SHA1 hashes; known magic inputs include `240610708` (MD5), `aaroZmOk` (SHA1) |
| **Boolean Coercion Bypass** | `true == "any_nonempty_string"` evaluates to `true`; sending `{"password": true}` via JSON bypasses hash comparison | `json_decode()` preserves boolean type; loose comparison against stored hash |
| **Null Equivalence Chain** | `NULL == false == "" == 0 == "0"` — all compare as equal under loose comparison, creating multiple bypass paths | Any loose comparison where one side can be null/empty |
| **Hex String Coercion** | `"0x1A" == 26` evaluates to `true`; hex string representation matched against integer | PHP 5.x only; removed in PHP 7.0 |
| **Numeric String Auto-Comparison** | Two numeric strings are compared as numbers, not lexicographically; `"10" == "1e1"` is `true` | Both operands are numeric strings |

### §3-2. PHP Function-Level Type Confusion

Several PHP standard library functions use loose comparison internally or have type-dependent behavior that attackers exploit.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **strcmp() with Array Input** | `strcmp()` returns `NULL` (not `0`) when given a non-string argument (e.g., array); `NULL == 0` is `true` under loose comparison | `strcmp($input, $secret) == 0` without strict comparison |
| **in_array() Without Strict Flag** | Third parameter `strict` defaults to `false`; `in_array("abc", [0,1,2])` is `true` because `"abc" == 0` | Missing `true` as third argument |
| **array_search() Loose Match** | Same behavior as `in_array()` but returns the matching key; `array_search(0, ["a","b","c"])` returns `0` (falsy — index 0 is falsy in boolean context, so `if(array_search(...))` treats a valid match as no-match) | Default loose comparison mode |
| **switch Statement Loose Matching** | `switch` uses loose comparison for case matching; `switch("any_string") { case 0: ... }` matches in PHP < 8.0 | Non-numeric string input matched against integer case |
| **preg_match() Return Type** | Returns `1` (match), `0` (no match), or `false` (error); `false == 0` is `true`, so error is indistinguishable from no-match under loose comparison | Error condition treated as "no match" |
| **json_decode() Type Injection** | Preserves JSON-native types (boolean, integer, null, array, object); `{"password": 0}`, `{"password": null}`, `{"password": []}` all bypass different comparison patterns | Application receives JSON and uses loose comparison on decoded values |

### §3-3. JavaScript Abstract Equality (==)

JavaScript's `==` operator follows the Abstract Equality Comparison Algorithm (ECMA-262 §7.2.14), which performs a cascade of type coercions (ToPrimitive, ToNumber, ToString) before comparison.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Array-to-Primitive Coercion** | `[] == false` is `true` ([] → "" → 0, false → 0); `[] == ![]` is `true` because `![]` = `false`, then `[] == false` | Loose comparison with array operand |
| **Object valueOf/toString Override** | Objects with custom `valueOf()` or `Symbol.toPrimitive` return attacker-controlled primitives during coercion; comparison evaluates against the return value, not the object | Object coercion invokes user-defined methods |
| **Null-Undefined Equivalence** | `null == undefined` is `true`; neither equals any other value under `==` | Authorization checks using `== null` inadvertently accept `undefined` (missing field) |
| **NaN Self-Inequality** | `NaN == NaN` is `false`; `NaN` is not equal to itself; bypasses deduplication, set membership, and cache lookups | Value is `NaN` from failed conversion (`parseInt("abc")`) |
| **Boolean-to-Number Shortcut** | `true == 1` and `false == 0`; sending `{"role": true}` matches `role == 1` check | JSON-delivered boolean compared against integer |

### §3-4. Python Comparison Edge Cases

Python is strongly typed in comparison but has specific equivalence rules that create confusion.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boolean-Integer Equivalence** | `True == 1`, `False == 0`, `True in [1,2,3]` is `True`; `{True: "a", 1: "b"}` creates a single-key dict | Boolean and integer are interchangeable in comparisons and hashing |
| **NaN Dictionary Key Bypass** | `float('nan')` as a dict key can be inserted multiple times because `NaN != NaN`; lookups fail for existing NaN keys | NaN used as cache key, dedup key, or set element |
| **Subclass isinstance() Bypass** | `isinstance(MaliciousStr(), str)` is `True` for a subclass that overrides `__eq__`, `__hash__`, or security-relevant methods | Security gate uses `isinstance()` instead of `type() is` |

---

## §4. Implicit Numeric Conversion

Numeric type coercion occurs when strings, booleans, nulls, or other non-numeric values are implicitly converted to numbers (or vice versa). Precision loss, truncation, and representation differences between numeric types create exploitable divergences.

### §4-1. String-to-Number Coercion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Leading Non-Numeric Truncation** | `parseInt("123abc")` returns `123`; `parseInt("")` returns `NaN`; `Number("")` returns `0` | JavaScript `parseInt` ignores trailing non-numeric characters |
| **Scientific Notation Interpretation** | `"1e2"` parsed as `100` in numeric context; WAFs checking for string `"100"` miss the `"1e2"` representation | Any context where string-to-number conversion accepts scientific notation |
| **Octal/Hex String Prefix** | `parseInt("0x10")` returns `16`; `parseInt("010")` returns `8` (legacy) or `10` (modern); `"0x1A" == 26` in PHP 5.x | Inconsistent base handling across parsers; leading-zero ambiguity |
| **MySQL String-to-Integer Coercion** | `SELECT * FROM users WHERE username = 0` returns ALL rows because non-numeric strings coerce to `0`, making `'admin' = 0` true | Integer operand forces string column to coerce; no type-safe comparison |
| **MySQL Truncation Coercion** | `WHERE id = '1abc'` truncates to `1` and returns `id=1` row with a warning (not error) | String value with leading digits matched against integer column |
| **Integer-String Conversion DoS** | `int("1" + "0" * 1000000)` has O(n²) complexity in Python < 3.11, pinning CPU for seconds per call. Any JSON API parsing user-provided large integers is vulnerable. Fixed in Python 3.11+ via `sys.set_int_max_str_digits()` (default 4300 digit limit) | Python < 3.11; integer in JSON/form data exceeds 4300 digits (CVE-2020-10735) |

### §4-2. Integer-to-Float Precision Loss

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON Large Integer Precision Loss** | JavaScript `JSON.parse` loses precision for integers above `2^53`; Python preserves arbitrary precision; Go loses precision when unmarshaling to `float64` | Same JSON document parsed by different language parsers; authorization checked by one parser, data served by another |
| **Database Integer Overflow** | `SELECT ~0` yields `18446744073709551615` (max unsigned BIGINT); arithmetic overflow triggers error-based data extraction | MySQL BIGINT overflow used for error-based SQL injection |
| **Float-to-Integer Truncation** | `(int)3.999` yields `3`; `(int)-0.5` yields `0`; price calculations using float-to-int conversion lose fractional amounts | Currency calculations; quantity checks; array index derivation from float |

### §4-3. Character Encoding as Numeric Coercion

Character encoding transformations can function as implicit type coercion when character byte values are transformed by the OS or framework.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Windows Best-Fit Character Mapping** | Windows maps Unicode characters to "best-fit" ASCII equivalents: soft hyphen `0xAD` → regular hyphen `0x2D` (`-`); this coerces a benign character into a CLI argument prefix | PHP-CGI on Windows; CVE-2024-4577 used this to bypass argument injection fix (CVSS 9.8) |
| **Unicode Normalization Coercion** | NFC/NFD normalization transforms visually similar characters to canonical forms; `ℌ` (U+210C) normalizes to `H`; bypasses character-level blocklists | Blocklist applied before normalization; normalized value matches blocked pattern (cross-reference: §6 encoding-parser/unicode) |

---

## §5. Boolean, Null, and Undefined Coercion

Boolean and null coercion creates security-relevant divergence when authorization checks, validation gates, or flow control depend on truthiness of values whose type is not enforced.

### §5-1. Truthy/Falsy Divergence Across Languages

Different languages define different sets of "falsy" values, creating cross-language and cross-context confusion.

| Value | PHP | JavaScript | Python | Ruby |
|---|---|---|---|---|
| `false` | falsy | falsy | falsy | falsy |
| `0` | falsy | falsy | falsy | **truthy** |
| `""` | falsy | falsy | falsy | **truthy** |
| `"0"` | **falsy** | **truthy** | **truthy** | **truthy** |
| `null`/`None`/`nil` | falsy | falsy | falsy | falsy |
| `undefined` | — | falsy | — | — |
| `[]` (empty array) | **falsy** | **truthy** | **falsy** | **truthy** |
| `{}` (empty object) | — | **truthy** | **falsy** | **truthy** |
| `NaN` | — | falsy | — | — |

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PHP "0" Falsiness** | `"0"` is falsy in PHP but truthy in every other language; `if ($input)` rejects the string `"0"` | Validation treats `"0"` as empty/invalid; bypass or data loss |
| **JavaScript Empty Array Truthy** | `[]` is truthy in JS but falsy in Python/PHP; `if (arr)` does not check array emptiness | Authorization check assumes truthy implies non-empty |
| **Ruby Zero Truthy** | `0` and `""` are truthy in Ruby; `if input` does not catch zero or empty string | Ruby application incorrectly assumes `if value` validates non-zero |

### §5-2. Null vs. Missing vs. Empty String

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON null vs. Absent Field** | `{"field": null}`, `{"field": ""}`, and `{}` (absent) are three distinct states; backend `if (data.field)` handles them differently depending on language | Authorization/validation skips null or absent values entirely |
| **SQL NULL Propagation** | `NULL = NULL` is `NULL` (not `true`); `WHERE field = NULL` matches nothing; `WHERE field IS NULL` required | Comparison with NULL intended to match NULL values |
| **Optional/Maybe Type Confusion** | Strongly-typed languages wrapping nullable types can confuse "no value" with "null-like value": Java `Optional.ofNullable(null)` vs. `Optional.empty()` (note: `Optional.of(null)` throws `NullPointerException`); Rust `Option<Option<T>>` where `None` vs. `Some(None)` diverge; Swift optional chaining where `nil` at different nesting levels produces different results | Unwrapping logic doesn't distinguish "no value" from "value is null" — mechanism differs per language |

### §5-3. Boolean-to-Integer Implicit Conversion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON Boolean in Numeric Context** | `true` sent via JSON where an integer is expected; `true == 1` passes numeric checks in JS/PHP; `true > 0` passes threshold checks | API endpoint accepts JSON without type validation |
| **Rails Boolean Column Coercion** | ActiveRecord boolean columns accept `"true"`, `"t"`, `"yes"`, `"1"`, `1` as `true` and their inverses as `false` | Mass assignment sends `"1"` for boolean field expecting only form checkbox input |
| **Python Boolean Arithmetic** | `True + True = 2`; `sum([True, True, False]) = 2`; boolean values participate in arithmetic as integers | Counter or threshold logic using boolean summation |

---

## §6. Serialization and Deserialization Boundaries

Type confusion at serialization boundaries occurs when the serialization format can represent types that the consuming code doesn't expect, or when the deserialization process instantiates arbitrary types based on attacker-controlled type metadata.

### §6-1. JSON Type Preservation and Divergence

JSON's type system (string, number, boolean, null, array, object) is simpler than any programming language's type system. `json_decode()` / `JSON.parse()` / `json.loads()` preserve JSON-native types, delivering unexpected types to code that assumes strings.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boolean Injection via JSON** | Sending `{"password": true}` delivers a boolean where a string hash is expected; `true == "hash_string"` is `true` under PHP loose comparison | PHP loose comparison on `json_decode()` output |
| **Integer Injection via JSON** | Sending `{"count": 0}` or `{"id": -1}` delivers an integer where a string is expected; `0 == "string"` is `true` in PHP < 8.0 | Type-dependent comparison without strict checking |
| **Null Injection via JSON** | `{"token": null}` delivers null where a string is expected; `null == false == ""` chain bypasses various checks | Loose equality or truthiness checks on decoded values |
| **Array/Object Injection via JSON** | `{"password": []}` or `{"role": {"$gt": ""}}` delivers structured types where scalars are expected; functions receiving wrong types return unexpected values or trigger NoSQL operators | No type validation at deserialization boundary |
| **Duplicate Key Divergence** | `{"role":"user","role":"admin"}` — most parsers take the last value, some take the first; WAF and backend may parse differently | No standard behavior for duplicate JSON keys (RFC 8259 says "SHOULD be unique") |

### §6-2. Pickle Arbitrary Type Instantiation (Python)

Python's `pickle` protocol allows serialized data to specify arbitrary class constructors via the `__reduce__` method. Deserialization instantiates whatever type the payload specifies.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **__reduce__ RCE** | Pickled object defines `__reduce__` returning `(os.system, ("command",))`; `pickle.loads()` executes the command | Application deserializes untrusted pickle data |
| **Nested Gadget Chain** | Multiple pickle opcodes combined to construct complex exploitation chains: `GLOBAL`, `REDUCE`, `BUILD`, `INST` opcodes sequence arbitrary operations | Any `pickle.loads()` on untrusted input; all pickle protocols (0–5) |
| **copyreg Abuse** | Custom dispatch table in `copyreg` module redirects pickle construction to attacker-chosen functions | Application uses custom pickle dispatch without restricting callable types |

### §6-3. YAML Tag-Controlled Type Instantiation

YAML's tag system allows explicit type annotation. PyYAML's `yaml.load()` (without `SafeLoader`) interprets tags as Python type constructors.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **!!python/object/apply RCE** | `!!python/object/apply:os.system ["id"]` — tag specifies callable, sequence specifies arguments | `yaml.load()` or `yaml.load(data, Loader=Loader)` on untrusted input |
| **!!python/object/new Constructor** | `!!python/object/new:subprocess.check_output [["whoami"]]` — instantiates arbitrary class | Same condition; `yaml.safe_load()` is the only safe alternative |
| **Ruby YAML Deserialization** | `!ruby/object:Gem::Installer` and similar tags instantiate arbitrary Ruby objects with attacker-controlled attributes | Ruby application using `YAML.load()` on untrusted input |

### §6-4. Protobuf Wire Type and Schema Confusion

Protocol Buffers encode fields with wire types (varint, fixed32, fixed64, length-delimited) independent of the logical schema type. Mismatches between sender and receiver schemas create type confusion at the wire level.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Wire Type Mismatch** | Field declared as `int32` (varint) in sender's schema but `string` (length-delimited) in receiver's; parser reinterprets varint bytes as length prefix, consuming arbitrary subsequent bytes | Schema evolution without coordinated deployment |
| **Any Type URL Spoofing** | `google.protobuf.Any` stores `type_url` string and raw bytes; attacker sets `type_url` to a different message type than the bytes represent; receiver deserializes as wrong type | No `type_url` validation against expected types |
| **Schema Evolution Supply Chain** | Attacker controlling a `.proto` dependency changes a field from `int32` to `string` while keeping the same field number; old clients send integers that new servers interpret as length-prefixed strings | Transitive `.proto` dependencies without integrity verification |
| **oneof Field Type Confusion** | `oneof` union allows different types for the same logical field; parser may accept a type the application doesn't handle, passing raw bytes to typed code | Missing exhaustive case handling for oneof variants |

### §6-5. XML Schema Type Override

XML allows `xsi:type` attributes to override element types defined in the schema. SOAP services using XML Schema validation can be attacked by asserting a different type than expected.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **xsi:type Override** | `<password xsi:type="xsd:boolean">true</password>` — schema says string but attacker asserts boolean; parser may coerce before comparison | SOAP service trusts `xsi:type` without restricting valid type assertions |
| **XXE into Typed Fields** | XML entity expansion injects arbitrary string content into fields expecting specific types (integer, boolean); lack of type enforcement allows injected data to propagate | XXE vulnerability in typed XML parser (cross-reference: injection/xxe) |

### §6-6. Zero-Copy Deserialization

Performance-optimized serialization formats that interpret byte buffers directly as typed structures (FlatBuffers, Cap'n Proto, rkyv) trade runtime type verification for speed.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Buffer Layout Reinterpretation** | Crafted buffer tricks zero-copy deserializer into reading fields at wrong offsets; no runtime type check on deserialized structure | Untrusted buffer input; missing verifier pass |
| **Enum Discriminant Out-of-Range** | Rust rkyv interprets raw bytes as enum discriminant; crafted value selects a variant the compiler considers impossible, violating niche optimization invariants | `unsafe` deserialization trust of external discriminant values |

---

## §7. Database Query Type Coercion

Database engines perform implicit type conversions when comparing values of different types in queries. This creates SQL injection amplification, authentication bypasses, and data extraction paths.

### §7-1. SQL Implicit Type Cast

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **String Column vs. Integer Literal** | `WHERE username = 0` — MySQL coerces all non-numeric string values to `0`, returning all rows where username is a non-numeric string | Integer literal compared against string column without parameterized query |
| **Integer Column vs. String Literal** | `WHERE id = '1abc'` — MySQL truncates string to `1` with a warning (not error), returning `id=1` row | String with leading digits compared against integer column |
| **Boolean Literal Injection** | `WHERE active = TRUE` — in MySQL, `TRUE` = `1`; in PostgreSQL, `TRUE` is a distinct boolean type; cross-database code may have different behavior | Database migration between MySQL and PostgreSQL |
| **Float vs. Integer Comparison** | `WHERE price = 19.99` — float comparison may not match stored decimal `19.99` due to IEEE 754 representation | Floating-point comparison against DECIMAL column |

### §7-2. NoSQL Operator Injection via Type Confusion

MongoDB and similar document databases accept query operators as nested objects. When a web framework parses user input into an object instead of a string, the object becomes a query operator.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **$ne Operator Injection** | `{"password": {"$ne": ""}}` — MongoDB matches all documents where password is not empty; bypasses authentication | Express.js body-parser delivers JSON objects; no type validation before query construction |
| **$gt / $lt Operator Injection** | `{"password": {"$gt": ""}}` — matches all non-empty passwords; enables binary search extraction via `{"password": {"$regex": "^a"}}` | Same framework-level type confusion |
| **$regex Pattern Injection** | `{"password": {"$regex": ".*"}}` — matches everything; character-by-character extraction via regex prefix narrowing | Same condition; enables full credential extraction |
| **$exists / $type Operator Injection** | `{"field": {"$exists": true}}` or `{"field": {"$type": 2}}` (type 2 = string) — metadata queries injected as field values | Same condition; enables schema discovery |

### §7-3. JSON Column Type Confusion

Modern databases support JSON columns with type-aware querying. The interaction between SQL types and JSON types creates additional confusion surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON Boolean vs. String Boolean** | `json_col->'$.admin' = true` (JSON boolean) vs. `json_col->'$.admin' = 'true'` (JSON string) — different semantics, different results | Application mixes JSON boolean and string representations |
| **JSON Number Precision** | Large integers in JSON columns may lose precision when extracted via SQL functions that use float intermediates | JSON column stores `9999999999999999999`; extraction function truncates |

---

## §8. Object Binding and Property Resolution

Frameworks that automatically bind input data to object properties create type confusion when the input type differs from the model's expected type, or when the binding mechanism resolves properties through prototype chains.

### §8-1. Mass Assignment Type Coercion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boolean Field Injection** | `{"is_admin": true}` via JSON body; framework auto-binds to model's boolean field | No allowlist/denylist for bindable properties; framework coerces input types to match model |
| **String-to-Boolean Coercion** | Rails ActiveRecord accepts `"true"`, `"t"`, `"yes"`, `"1"`, `1` as boolean `true` | Broader coercion surface than expected; attacker finds accepted representations |
| **Spring WebDataBinder Coercion** | Spring MVC binds request parameters to Java object fields with type conversion; `role=1` bound to `Role` enum via ordinal; `isAdmin=on` bound to boolean `true` | Default binder settings; no `@InitBinder` restriction |
| **Nested Object Injection** | `{"profile": {"role": "admin"}}` — framework traverses nested objects, binding deeply | Deep object binding enabled by default (e.g., Spring, Rails) |

### §8-2. Prototype Pollution Leading to Type Confusion

JavaScript prototype pollution injects properties into `Object.prototype`, which are then inherited by all objects. This creates a form of universal type confusion where any object appears to have attacker-controlled properties.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Property Existence Confusion** | Polluting `Object.prototype.isAdmin = true` makes `obj.isAdmin` truthy for all objects without their own `isAdmin` property | Authorization check: `if (user.isAdmin)` without `hasOwnProperty` |
| **instanceof Override via Symbol.hasInstance** | Polluting `Symbol.hasInstance` on a specific constructor's prototype can alter that constructor's `instanceof` results. Note: ordinary function constructors inherit `Function.prototype[Symbol.hasInstance]` which takes precedence over `Object.prototype` pollution — exploitable mainly when the target is a non-function object used as a right-hand operand, or via direct constructor prototype pollution | Security gate using `instanceof` for type checking against a non-function or pollutable constructor |
| **Constructor/Tag Spoofing** | Polluting `Symbol.toStringTag` or `constructor.name` defeats type-checking patterns like `Object.prototype.toString.call()` | Runtime type identification relying on string representations |
| **JSON Schema Validation Bypass** | Polluting properties that shadow JSON Schema meta-fields (e.g., `additionalProperties`, `required`) alters validation behavior | Server-side JSON Schema validation on objects with polluted prototypes |

### §8-3. DOM Clobbering

HTML elements create named properties on `document` and `window` that shadow JavaScript globals. This causes type confusion where code expects a function or object but receives an `HTMLElement`.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Named Element Global Override** | `<img name="createElement">` makes `document.createElement` return the HTMLImageElement instead of the function | Code accesses `document.propertyName` without checking type |
| **Anchor href toString** | `<a id="config" href="javascript:alert(1)">` — `config.toString()` returns the href; code expecting a string config value gets an attacker-controlled URL | Code accesses `window.config` and coerces to string |
| **Form Element Collection Shadowing** | `<form id="x"><input name="action" value="evil">` — `form.action` returns the input element, not the form's action URL | Code reads form properties expecting string values |

### §8-4. Express.js Query String Parser Object Injection

Express.js with the `qs` parser (extended mode) converts query string syntax into nested objects and arrays.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Array-to-Object Promotion** | `?password[$ne]=1` becomes `{password: {"$ne": "1"}}` — string parameter becomes MongoDB operator object | `express.urlencoded({extended: true})` or `qs` parser enabled |
| **Prototype Property Injection** | `?__proto__[isAdmin]=true` — some parsers set properties on `__proto__`, achieving prototype pollution via query string | Older `qs` versions or custom parsers without prototype sanitization |

---

## §9. API and Protocol Parameter Types

APIs and network protocols carry typed parameters across system boundaries. Divergent type parsing between API layers creates exploitable confusion.

### §9-1. GraphQL Type Coercion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Scalar Type Coercion to SQL** | `updateUser(id: "1 OR 1=1")` — GraphQL `ID` scalar accepts string; implementation passes directly to SQL without parameterization | GraphQL resolver concatenates coerced scalar into SQL |
| **Variable Type Bypass** | `$id: ID!` declared but `{"id": 0}` or `{"id": 99999}` sent as variables; integer coerced to `ID` string. Per GraphQL spec, `ID` input coercion accepts only string and integer — boolean values like `{"id": true}` are a request error in spec-compliant implementations | Lenient variable coercion in non-compliant GraphQL engines, or integer-to-string coercion surprising the resolver |
| **Batching Array Confusion** | Single query object expected, but array `[{query1}, {query2}]` sent; middleware inspects only first element for authorization; second element executes unauthorized | Array vs. object ambiguity at the HTTP-to-GraphQL boundary |

### §9-2. gRPC and Protobuf Parameter Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON Transcoding Type Mismatch** | gRPC-JSON transcoding converts JSON string `"123"` to protobuf `int32` field; different validation at JSON layer vs. protobuf layer | grpc-gateway or Envoy JSON transcoding without strict type enforcement |
| **Repeated vs. Scalar Field** | Client sends a single value for a `repeated` field or an array for a scalar field; parser behavior varies by implementation | Schema evolution; client and server have different proto versions |

### §9-3. HTTP Header and Content-Length Parsing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Content-Length Type Parsing Divergence** | Frontend parses `Content-Length` as string (taking first value), backend parses as integer (ignoring whitespace/signs); leading zeros, signs, or decimal points handled differently | Multiple `Content-Length` values or unusual numeric representations (cross-reference: http-protocol/request-smuggling) |
| **Header Value Type Confusion** | Numeric header expected but string sent (or vice versa); `X-Request-Count: abc` → `parseInt("abc") = NaN` → `NaN > 100 = false` → rate limiter bypass | Header-based rate limiting or threshold checking with coercion |
| **Content-Type Comma-Separated Value Differential** | RFC 9110 defines `Content-Type` as a singleton field, but browsers (Chromium, Firefox) parse it as a list-based field — splitting on commas and using the last syntactically valid value. Server-side libraries parse only the first value. Payload: `application/json;,text/html` — server validates as `application/json` (passes allowlist), browser renders as `text/html` (enables reflected XSS). Dangerous pattern: developers validate the parsed MIME type but reflect the original unparsed `Content-Type` value in the response | Application reflects user-controlled Content-Type in response; server-side MIME parser takes first value (Python `email.message`, `werkzeug.http`, Node.js `content-type`, PHP `fileeye/mimemap`); browser takes last value |
| **Content-Type Parenthesis-as-Comment (Chromium)** | Chromium treats parentheses in MIME parameters as RFC 822-style comments. `application/json;,text/html(=` bypasses stricter server-side parsers that reject unbalanced syntax (e.g., `whatwg-mimetype`, Go `mime.ParseMediaType`) while Chromium strips the parenthesized content and renders as `text/html` | Chromium browser; server parser rejects simple comma payloads but accepts parenthesized variants |

### §9-4. JSON Integer Precision Across Parsers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cross-Parser IDOR** | Same JSON integer parsed by JavaScript client (loses precision above `2^53`), Python API gateway (preserves precision), and Go backend (loses precision if `float64` target); authorization checked against one value, data served for another | Multi-language microservice architecture; large integer IDs |
| **BigInt Boundary Confusion** | Values between `Number.MAX_SAFE_INTEGER` and `2^64` behave differently across parsers; some round, some truncate, some error | API contract doesn't specify integer precision guarantees |

### §9-5. LLM Tool-Use Type Coercion

A novel attack surface emerging from AI systems making function calls.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Adversarial Prompt Type Confusion** | Adversarial prompt causes LLM to emit `{"user_id": "1; DROP TABLE users"}` (string) where schema expects integer; downstream API performs implicit coercion, enabling injection | LLM function-calling without strict type enforcement at the tool execution boundary |
| **Schema Mismatch Exploitation** | LLM's internal type model diverges from the actual API schema; adversarial input exploits the gap between what the LLM "thinks" the type should be and what the API accepts | Loosely-defined tool schemas; no runtime type validation layer |

---

## §10. Cross-Language and FFI Boundaries

Every language boundary is a potential type confusion point. Type systems are not preserved across FFI, serialization, or runtime interop boundaries, creating gaps where values can be reinterpreted.

### §10-1. JVM Type Erasure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Generic Collection Type Confusion** | `List<String>` and `List<Int>` are both `List` at runtime; attacker injecting values into a generic collection bypasses compile-time type safety | Reflection, serialization, or mixed-language JVM access (Groovy, Clojure injecting into Java generics) |
| **Bridge Method Invocation** | JVM compiler generates bridge methods for generic type specialization; reflective invocation of bridge method bypasses type checks | Reflection-based frameworks (Spring, Hibernate) invoking generic methods |

### §10-2. Swift-Objective-C Bridging

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **id-to-Any Bridging Confusion** | Objective-C `id` maps to Swift `Any`; force-downcast (`as!`) without checking creates runtime type confusion when Objective-C returns unexpected type | IOKit interfaces returning `id`; CVE-2024-27804 exploited this for kernel-level type confusion |
| **NSNumber Boxing Ambiguity** | Objective-C `NSNumber` boxes both integers and booleans; `@YES` (boolean) and `@1` (integer) are the same `NSNumber` in some contexts | Swift code interpreting `NSNumber` differently based on assumed original type |

### §10-3. Rust Unsafe and FFI

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **transmute Type Confusion** | `std::mem::transmute` reinterprets bytes as a different type without any validation; wrong type annotation creates immediate type confusion | `unsafe` block with incorrect type parameter |
| **Trait Object vtable Swap** | `dyn Trait` fat pointer contains `(data_ptr, vtable_ptr)`; unsafe code constructing trait objects can swap vtable pointers, redirecting method dispatch | Custom unsafe downcasting in plugin systems |
| **FFI Type Width Mismatch** | C `int` is 32-bit on most platforms but Rust `c_int` mapping may not match on exotic targets; sign extension and truncation at FFI boundary | Cross-platform code with `extern "C"` functions |

### §10-4. Go Type Assertion Failures

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Interface Type Assertion Panic** | `value.(ConcreteType)` panics if the actual type doesn't match; unrecovered panic in a server handler crashes the service (DoS) | Missing comma-ok pattern: `value, ok := iface.(Type)` |
| **encoding/json Untyped Unmarshaling** | `json.Unmarshal` into `interface{}` produces `float64` for all numbers, `map[string]interface{}` for objects; downstream code asserting `int` gets `float64` | JSON unmarshaled into generic types without explicit struct targets |
| **reflect Type Confusion** | `reflect.Value` operations on wrong type cause panics or return garbage; `reflect.ValueOf(ptr).Elem()` on non-pointer panics | Dynamic type manipulation without proper type checking |
| **encoding/xml Namespace Handling Quirks** | Go's `encoding/xml` decoder handles XML namespaces inconsistently compared to standard XML parsers (libxml2, Java SAX/DOM) — it may silently ignore namespace prefixes, flatten namespace-qualified attributes, or accept malformed namespace declarations that strict parsers reject. When an XML security decision (SAML signature validation, SOAP routing) is made by a standard-compliant parser but the data is consumed by Go's `encoding/xml`, the discrepancy enables element injection or signature wrapping bypass | Go service validates or processes XML alongside another system using a different XML parser; namespace-sensitive security logic (Trail of Bits "Unexpected Security Footguns in Go's Parsers" research, 2025) |
| **encoding/xml Directive Processing Differential** | Go's XML decoder processes `<!DOCTYPE>` and processing instructions differently from libxml2 or Java parsers. Payloads that would be rejected by standard XML parsers (e.g., certain entity declarations, nested DTD constructs) may be silently accepted by Go's decoder, or vice versa — creating bypass opportunities in systems that assume uniform XML parsing behavior | Go service receiving XML from external sources; assumption that Go's XML parser is "safe by default" due to lack of external entity support |
| **encoding/json Duplicate Key Divergence** | Go's `json.Unmarshal` takes the **last** value when duplicate keys exist in a JSON object. This differs from Python (`json.loads` takes last), PHP (`json_decode` takes last), Ruby (takes last), but critically from some middleware or WAFs that may inspect the **first** value. An attacker includes `{"role":"user","role":"admin"}` — the WAF validates `"user"` while Go's handler processes `"admin"` | Multi-layer architecture where JSON is validated/inspected at one layer and consumed at another; duplicate keys in request body |

### §10-5. Wasm-JS Interop

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **i64 Truncation at JS Boundary** | Wasm `i64` values passed to JavaScript are truncated to `Number` (losing precision above `2^53`) or require `BigInt` handling that may not be implemented | Wasm module returning large integers consumed by JS code |
| **Component Model Type Confusion** | Wasm Component Model introduces interface types (records, variants, lists) with cross-module linking; structural subtyping may permit semantically incompatible types | Multi-module Wasm applications with shared interface types |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|---|---|---|---|
| **Authentication Bypass** | Web application with loose comparison or NoSQL backend | §3 (comparison operators), §6-1 (JSON type injection), §7-2 (NoSQL operators) | Account takeover |
| **Remote Code Execution (Browser)** | Chromium/Firefox/Safari rendering untrusted content | §2 (JIT speculation), §2-5 (Wasm) | Full host compromise via sandbox escape chain |
| **Remote Code Execution (Server)** | Python/Ruby application deserializing untrusted data | §6-2 (Pickle), §6-3 (YAML), §6-4 (Protobuf) | Server takeover |
| **Arbitrary Memory Read/Write** | C/C++ application or kernel with type-confused pointer | §1 (memory layout), §1-2 (vtable), §1-3 (union) | Kernel privilege escalation |
| **Injection Amplification** | Web application where type confusion enables SQL/NoSQL injection | §7-1 (SQL coercion), §7-2 (NoSQL operators), §8-4 (qs parser) | Data exfiltration, full database access |
| **WAF/Filter Bypass** | Request inspected by WAF, processed by backend with different type semantics | §4-1 (numeric representation), §4-3 (encoding coercion), §9-3 (header parsing) | Bypass of security controls |
| **Privilege Escalation** | Application with mass assignment or prototype pollution | §8-1 (mass assignment), §8-2 (prototype pollution), §5-3 (boolean coercion) | Admin access, elevated roles |
| **Information Disclosure** | Application leaking data via precision difference or NaN behavior | §4-2 (precision loss), §9-4 (cross-parser IDOR), §3-4 (NaN) | PII exposure, credential leakage |
| **Denial of Service** | Go/Rust service with unhandled type assertion failures | §10-4 (Go panic), §1-3 (enum discriminant corruption) | Service crash |
| **Supply Chain Exploitation** | Schema dependency controlled by attacker | §6-4 (Protobuf schema evolution), §10-5 (Wasm Component Model) | Persistent backdoor via type confusion |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 + §2-4 (V8 JIT type speculation + guard elimination) | CVE-2024-0517 (Chrome V8) | OOB write; public bounty case |
| §2-5 (Wasm cross-module type validation) | CVE-2024-2887 (Chrome V8 Wasm) | Full chain RCE; Pwn2Own Chrome exploit component |
| §2-1 (V8 Maglev type feedback) | CVE-2024-4947 (Chrome) | In-the-wild zero-day, APT espionage |
| §2-4 (V8 optimization pipeline) | CVE-2024-5274 (Chrome V8) | In-the-wild zero-day |
| §2-4 (V8 optimization) | CVE-2024-7971 (Chrome V8) | In-the-wild zero-day, Citrine Sleet + kernel exploit chain |
| §2-2 (SpiderMonkey range analysis) | CVE-2024-29943 (Firefox) | Bounds check bypass, CVSS 9.8 |
| §2 (Firefox event handler type confusion) | CVE-2024-29944 (Firefox) | Privileged JavaScript execution; Mozilla severity Critical. NVD currently shows no NIST/CNA score and reports CISA-ADP CVSS v3.1 8.4 |
| §1-2 (UAF-to-type-confusion on freed object) | CVE-2024-9680 (Firefox Animation) | In-the-wild zero-day, RomCom APT, CVSS 9.8 |
| §2-1 (JSC type speculation) | CVE-2024-23222 (Safari JSC) | In-the-wild zero-day, arbitrary memory R/W |
| §2-1 (JSC JIT type error) | CVE-2024-27834 (Safari JSC) | Pwn2Own 2024 |
| §2-1 (JSC Intel-specific type confusion) | CVE-2024-44308 (Safari JSC) | In-the-wild zero-day, Intel Mac target |
| §4-3 (Windows Best-Fit character mapping coercion) | CVE-2024-4577 (PHP-CGI Windows) | Argument injection via char coercion, CVSS 9.8 |
| §10-2 (Swift-ObjC id bridging + kernel objects) | CVE-2024-27804 (Apple XNU/IOKit) | Kernel type confusion, targeted exploitation |
| §2 (Windows JScript9 scripting engine) | CVE-2024-38178 (Windows JScript9) | In-the-wild zero-day, ScarCruft APT |
| §3-1 (PHP loose comparison) + §6-1 (JSON type injection) | Multiple HackerOne/Bugcrowd reports | Authentication bypass; bounty-confirmed reports |
| §7-2 (NoSQL operator injection) | Multiple Synack/HackerOne reports | Account takeover via MongoDB injection; bounty-confirmed reports |
| §9-4 (JSON integer precision loss) | Google VRP, Shopify reports | Cross-parser IDOR; bounty-confirmed reports |

---

## Detection Tools

### Static Analysis

| Tool | Target | Core Technique |
|---|---|---|
| **CodeQL** (GitHub) | C/C++, Java, JS, Python | Semantic query language; queries for `reinterpret_cast`, loose comparison, NoSQL injection |
| **PHPStan** (level 5+) | PHP | Detects loose comparison usage, type-dependent function calls, magic hash patterns |
| **Psalm** (Vimeo) | PHP | Taint analysis + type tracking; flags loose comparison in security-sensitive contexts |
| **ESLint eqeqeq rule** | JavaScript | Enforces `===`/`!==` over `==`/`!=` |
| **typescript-eslint strict-boolean-expressions** | TypeScript | Prevents truthy/falsy coercion in conditionals |
| **Coverity** | C/C++, Java | Interprocedural analysis for bad casts and incompatible pointer assignments |
| **Clang Static Analyzer** | C/C++ | `alpha.core.CastToStruct`, `optin.cplusplus.VirtualCall` checkers |
| **mypy --strict** | Python | Static type checking; catches `isinstance` vs `type()` confusion patterns |

### Dynamic Analysis / Sanitizers

| Tool | Target | Core Technique |
|---|---|---|
| **UBSan** (`-fsanitize=vptr`) | C/C++ | Runtime check for bad virtual calls and wrong dynamic types |
| **TypeSanitizer (TySan)** | C/C++ | Shadow memory tracking of per-location effective type; flags cross-type access |
| **AddressSanitizer (ASan)** | C/C++ | Detects UAF and buffer overflows that enable type confusion |
| **Clang CFI** (`-fsanitize=cfi-*`) | C/C++ | Validates cast targets, virtual call targets, indirect calls against expected types |
| **Zod / io-ts / Runtypes** | JavaScript/TypeScript | Runtime schema validation at API boundaries; enforces types that TypeScript erases |
| **beartype** | Python | O(1) runtime type checking decorator; validates function signatures at call time |

### Fuzzers

| Tool | Target | Core Technique |
|---|---|---|
| **Fuzzilli** (Google) | JavaScript JIT engines | Coverage-guided generation of semantically valid JS targeting type inference paths |
| **JIT-Picking** | JavaScript JIT engines | Differential fuzzing: interpreted vs. JIT-compiled execution comparison |
| **Domato** (Google) | Browser DOM engines | Grammar-based DOM API fuzzing targeting type confusion in binding layer |
| **AFL++** | C/C++ applications | Coverage-guided mutation fuzzing; combine with UBSan/CFI for type confusion detection |

### Architectural Defenses

| Defense | Scope | Mechanism |
|---|---|---|
| **V8 Sandbox / Memory Cage** | Chrome V8 heap | Isolates V8 heap; limits type confusion exploitation scope |
| **PartitionAlloc** | Chrome | Type-based heap partitioning; different types in separate pools |
| **Gigacage** | WebKit | Separate heap regions per object type |
| **ARM MTE** | Hardware | Per-allocation memory tags detect cross-type access |
| **ARM PAC** | Hardware | Cryptographic pointer authentication prevents pointer substitution |
| **Intel CET** | Hardware | Indirect Branch Tracking + Shadow Stack |
| **Site Isolation** | Browsers | Per-site OS processes limit cross-origin type confusion impact |

---

## References

- CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')
- CWE-704: Incorrect Type Conversion or Cast
- CWE-1287: Improper Validation of Specified Type of Input
- OWASP Testing Guide: Type Manipulation
- PHP Manual: Type Comparisons (php.net/manual/en/types.comparisons.php)
- ECMA-262: Abstract Equality Comparison Algorithm (§7.2.14)
- CAVER (IEEE S&P 2015), TypeSan (CCS 2016), HexType (CCS 2017): C++ type confusion detection lineage
- JIT-Picking (CCS 2022): Differential fuzzing for JIT type confusion
- V8 Blog: Sandbox architecture and type guard design
- RFC 8259: JSON data interchange format (duplicate key semantics)
- [Jake Miller (Bishop Fox) — "An Exploration of JSON Interoperability Vulnerabilities" (2021). Survey of 49 JSON parsers across 10 languages; documented duplicate key handling divergences, number precision differences, key collision attacks, and permissive parsing discrepancies enabling cross-parser smuggling.](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
