# PHP-Specific Vulnerabilities: Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy catalogs vulnerabilities **intrinsic to the PHP language**, its runtime, standard library, and interpreter — as opposed to generic web application vulnerabilities (SQLi, XSS) that merely happen to be written in PHP. The focus is on weaknesses that arise from PHP's design decisions, type system, built-in functions, configuration model, and C-level implementation.

The taxonomy is organized along three orthogonal axes:

**Axis 1 — Mutation Target (Primary Structure)**: The structural component of the PHP ecosystem being exploited. This axis defines the ten top-level sections (§1–§10) and determines where each technique lives in the document. Categories include the type system, serialization engine, stream wrappers, dynamic evaluation surface, configuration/runtime sandbox, variable scope mechanics, input validation functions, interpreter memory safety, randomness/cryptography primitives, and XML processing.

**Axis 2 — Discrepancy Type (Cross-Cutting)**: The nature of the security failure each mutation creates. These discrepancy types recur across multiple §-categories:

| Discrepancy Type | Description |
|-----------------|-------------|
| **Type Confusion** | PHP interprets a value's type differently than the developer intended |
| **Parser Differential** | Two PHP components (or PHP + OS) parse the same input differently |
| **Validation Bypass** | A security check is circumvented through unexpected input forms |
| **Sandbox Escape** | PHP's own security restrictions (disable_functions, open_basedir) are broken |
| **Memory Corruption** | The PHP interpreter's C-level memory is corrupted |
| **State Manipulation** | Internal application variables or configuration are overwritten |
| **Encoding/Charset Abuse** | Character encoding transformations produce unintended results |

**Axis 3 — Attack Scenario (Mapping)**: The weaponized outcome — RCE, authentication bypass, file read/write, SSRF, DoS, privilege escalation, or information disclosure. This axis is covered in the Attack Scenario Mapping table (§11).

---

## §1. Type System & Comparison Logic

PHP's dynamic type system performs implicit type coercion ("type juggling") during comparisons, arithmetic, and function calls. This design — intended for developer convenience — creates a systematic class of vulnerabilities where attackers manipulate input types to subvert security logic.

### §1-1. Loose Comparison Operator Abuse

PHP's `==` operator performs type coercion before comparison, converting operands to a common type. When security-critical comparisons (authentication checks, token validation, HMAC verification) use `==` instead of `===`, attackers can exploit coercion rules to produce unexpected equality.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **String-to-Integer Coercion** | Strings not beginning with a digit are coerced to integer `0`; `"admin" == 0` evaluates to `true` | PHP < 8.0; loose comparison with integer operand |
| **Magic Hash ("0e" Trick)** | MD5/SHA1 hashes starting with `0e` followed by only digits (e.g., `0e462097431906509019562988736854`) are interpreted as scientific notation (`0 * 10^N = 0`); two such hashes compare as equal | PHP < 8.0; hash comparison using `==` |
| **Boolean Coercion** | Non-empty strings coerce to `true`; `"anything" == true` evaluates to `true` | Loose comparison against boolean operand |
| **Null Coercion** | `NULL == false`, `NULL == 0`, `NULL == ""` all evaluate to `true` | Loose comparison where one operand may be NULL |
| **Numeric String Comparison** | `"0x1A" == 26` evaluates to `true` in PHP < 7.0 (hex string parsing); `"0" == false` is always `true` | PHP < 7.0 for hex; all versions for zero-string |

PHP 8.0 significantly mitigated string-to-integer coercion: non-numeric strings are no longer coerced to `0` when compared with `==`. However, other coercion vectors (boolean, null) remain.

### §1-2. Function-Level Type Confusion

Several PHP standard library functions exhibit unexpected behavior when receiving array inputs instead of strings, or when implicit type conversion produces unintended return values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **strcmp() Array Bypass** | `strcmp([], "password")` returns `NULL`; with loose comparison `NULL == 0` evaluates to `true`, bypassing password checks | `strcmp()` return value checked with `==` instead of `===` |
| **in_array() Loose Mode** | `in_array("0", ["admin"])` returns `false`, but `in_array(0, ["admin"])` returns `true` because the string is coerced to `0` | Default (non-strict) mode of `in_array()` |
| **switch/case Coercion** | `switch($input)` with `case 0:` matches any non-numeric string because the string is coerced to `0` | `switch` statement with integer cases and string input |
| **array_search() Bypass** | Like `in_array()`, default loose comparison allows type juggling to return incorrect matches | Default (non-strict) `array_search()` |
| **md5()/sha1() Array Bypass** | `md5([])` returns `NULL` with a warning; if two inputs both yield `NULL`, they compare as equal | Hash functions used on unvalidated input type |
| **intval() Truncation** | `intval("1e2")` returns `100`, `intval("0x1A")` returns `0` (PHP 7+) or `26` (PHP 5); exploitable in numeric validation | Version-dependent parsing rules |

### §1-3. json_decode() Type Manipulation

When user input passes through `json_decode()` before security checks, attackers control the exact PHP type of each value — integers, floats, booleans, arrays, objects — enabling precise type juggling attacks that are impossible with raw HTTP parameters (which are always strings).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Integer Injection** | Submitting `{"password": 0}` via JSON causes `0 == "admin_password"` to be `true` in PHP < 8.0 | JSON input + loose comparison |
| **Boolean Injection** | Submitting `{"is_admin": true}` via JSON where the app checks `$input == "some_value"` | JSON input + loose comparison against string |
| **Integer Overflow** | Submitting very large integers that overflow to `0` or `PHP_INT_MAX`, bypassing range checks | Platform-dependent integer size (32/64-bit) |
| **Float Precision** | Submitting `{"amount": 0.1}` exploits IEEE 754 floating-point imprecision in financial calculations | Float arithmetic used for monetary values |

---

## §2. Serialization & Object Lifecycle

PHP's `unserialize()` function reconstructs arbitrary objects from serialized strings, triggering magic methods (`__wakeup`, `__destruct`, `__toString`, `__call`) that can be chained into "gadget chains" achieving RCE, file operations, or SSRF. This is arguably PHP's most impactful vulnerability class.

### §2-1. Direct unserialize() Injection

The most straightforward vector: user-controlled data reaches `unserialize()` without sanitization, allowing the attacker to inject serialized objects with malicious property values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Magic Method Chains** | Injected objects trigger `__destruct()` or `__wakeup()` which call methods on other injected objects, forming a chain ending in `system()`, `eval()`, or file write | Gadget classes available in autoload path |
| **Property-Oriented Programming (POP)** | Chains constructed purely through property assignments and magic method invocations, analogous to ROP in binary exploitation | Sufficient class diversity in application/framework |
| **Partial Object Injection** | Only a substring of the serialized data is controlled; exploitation requires crafting valid serialization boundaries around the injection point | Serialized data is partially constructed server-side |
| **Allowed Classes Bypass** | `unserialize($data, ["allowed_classes" => [...]])` can be bypassed if the allowed list includes a gadget-capable class, or via nested serialization | PHP 7.0+ allowed_classes parameter |
| **Autoload-Triggered Unreachable Class Exploitation** | PHP's `spl_autoload` mechanism loads any class referenced in serialized data during `unserialize()`, even classes never instantiated in normal execution. This expands the gadget surface to the entire autoload path — classes from unused framework modules, optional dependencies, and development tools all become reachable gadgets despite being "unreachable" in application logic | Composer autoloader or `spl_autoload_register` configured; additional framework/library classes on the autoload path not directly used by the vulnerable endpoint |

### §2-2. PHAR Deserialization

PHAR (PHP Archive) files contain serialized metadata that is **automatically deserialized** when the file is accessed through any filesystem function using the `phar://` stream wrapper. This converts file operation primitives into deserialization attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **File Operation Trigger** | Any of 30+ filesystem functions (`file_exists`, `is_dir`, `fopen`, `copy`, `stat`, `filemtime`, etc.) on a `phar://` path triggers metadata deserialization | PHP < 8.0; attacker controls file path argument |
| **Polyglot PHAR** | PHAR files crafted as valid JPEG/GIF/PNG (polyglot files) to bypass upload filters while retaining PHAR functionality | Image upload + file operation on uploaded path |
| **Renamed Extension** | PHAR files with non-`.phar` extensions (`.jpg`, `.txt`) are still processed as PHAR when accessed via `phar://` wrapper | No extension whitelist on `phar://` access |

PHP 8.0 disabled automatic PHAR metadata deserialization, largely mitigating this class. However, applications explicitly using `Phar` class methods remain vulnerable.

### §2-3. Session-Based Deserialization

PHP session data is serialized/deserialized using a configurable handler (`php`, `php_serialize`, `php_binary`). Mismatches between handlers, or attacker-controlled session data, create deserialization vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Handler Mismatch** | `session.serialize_handler=php` uses `|` as key-value delimiter; if data written with `php_serialize` handler contains `|`, it creates injectable boundaries | Different handlers used for read vs. write, or between pages |
| **session.upload_progress Injection** | `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST data creates attacker-controlled session entries; combined with LFI on session files, achieves code execution | `session.upload_progress.enabled=On` (default) |
| **Race Condition Cleanup** | `session.upload_progress.cleanup=On` (default) deletes progress data after upload completes; exploitation requires race condition to read session file before cleanup | Requires concurrent requests |

### §2-4. Gadget Chain Ecosystem

PHP gadget chains are discovered in major frameworks and libraries, cataloged and automated by tools like PHPGGC.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Framework-Specific Chains** | Pre-built chains for Laravel, Symfony, WordPress, Drupal, Magento, Yii, CodeIgniter, Guzzle, Monolog, SwiftMailer, Doctrine | Target framework/library in autoload path |
| **Generic Chains** | Chains using PHP core classes or extremely common libraries (e.g., Monolog) that exist in most PHP applications | Widely-deployed dependency |
| **File Write Chains** | Chains that achieve arbitrary file write (e.g., writing a webshell) rather than direct command execution | Write-capable gadget class available |
| **SSRF Chains** | Chains triggering outbound HTTP requests to attacker-controlled or internal services | HTTP client library in autoload path |

---

## §3. File Inclusion & Stream Wrappers

PHP's `include`/`require` statements interpret included content as PHP code. Combined with PHP's rich stream wrapper system, file inclusion vulnerabilities escalate from information disclosure to RCE through multiple exploitation paths.

### §3-1. Classic File Inclusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Local File Inclusion (LFI)** | Attacker controls part of a file path passed to `include()`, reading arbitrary local files that are then parsed as PHP | Unsanitized user input in include path |
| **Remote File Inclusion (RFI)** | When `allow_url_include=On`, remote URLs can be included, directly loading attacker-controlled PHP code | `allow_url_include=On` (disabled by default since PHP 5.2) |
| **Null Byte Truncation** | Appending `%00` to the path truncates appended extensions: `include($_GET['f'].'.php')` becomes `include("../../etc/passwd\0")` | PHP < 5.3.4 |
| **Path Truncation** | Paths longer than 4096 bytes are silently truncated by the OS, dropping appended extensions | PHP < 5.3 on most systems |
| **Double Encoding** | URL-encoding traversal sequences twice (`%252e%252e%252f`) to bypass single-decode filters | Application performs single URL decode |

### §3-2. PHP Stream Wrapper Exploitation

PHP registers numerous stream wrappers (`php://`, `data://`, `phar://`, `zip://`, `expect://`, `glob://`) that transform file operations into diverse attack primitives.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **php://filter (Read)** | `php://filter/convert.base64-encode/resource=config.php` reads source code without execution, enabling credential extraction | LFI primitive; no special config needed |
| **php://filter Chain RCE** | Chaining character encoding conversions (`convert.iconv.X.Y`) to construct arbitrary byte sequences, achieving file write or code execution from a read-only LFI | LFI primitive; PHP compiled with iconv |
| **php://input** | `include("php://input")` reads raw POST body as PHP code; requires `allow_url_include=On` | `allow_url_include=On` |
| **data:// Wrapper** | `include("data://text/plain;base64,PD9waHA...")` embeds PHP code directly in the URL | `allow_url_include=On` |
| **zip:// Wrapper** | `include("zip:///tmp/evil.zip#shell.php")` extracts and executes a file from within an uploaded ZIP archive | Attacker can upload ZIP to known path |
| **expect:// Wrapper** | `include("expect://id")` executes OS commands directly | `expect` PECL extension installed |
| **php://filter Prefix/Suffix Injection (wrapwrap)** | Chaining `php://filter` with specific `convert.iconv` encodings to prepend or append arbitrary content to a file read. By controlling the prefix and suffix of the filter output, an attacker transforms a read-only LFI into XXE, SSRF, or deserialization triggers — wrapping the file contents inside attacker-controlled XML/serialized envelopes without any file write | LFI primitive; PHP compiled with iconv; target parser processes the wrapped output (e.g., XML parser, unserialize) |
| **glob:// Wrapper** | `glob://` can enumerate directories even under `open_basedir` restrictions | `open_basedir` active; used for reconnaissance |

### §3-3. PHP Filter Chain Oracle

A technique for exfiltrating file contents character-by-character through error-based oracle attacks on PHP filter chains.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Error-Based Oracle** | Specific filter chain combinations produce errors (or not) depending on the byte value at a position, allowing binary search over each character | LFI primitive with observable error behavior |
| **Lightyear Technique** | Optimized oracle exploitation using iconv conversion sequences; computes jump sequences to read individual digits with ~6 requests per character | LFI + iconv support; leverages CVE-2024-2961 for enhanced capability |
| **Memory Exhaustion Oracle** | Specific filter chain combinations cause PHP to allocate exponentially growing memory when the target byte matches a condition, triggering a fatal error (memory limit exceeded) that is distinguishable from a normal response. By binary-searching each byte position, file contents are extracted without direct output | LFI primitive with observable error/crash behavior; PHP memory_limit configured (default) |

### §3-4. LFI-to-RCE Escalation Paths

Beyond stream wrappers, several PHP-specific mechanisms convert LFI to code execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Log Poisoning** | Inject PHP code into server logs (access log, error log, mail log) via User-Agent, Referer, or other logged fields; then include the log file | Log file path known and readable |
| **Session File Inclusion** | Include PHP session files (`/tmp/sess_XXXXX`) after injecting PHP code into session data via `PHP_SESSION_UPLOAD_PROGRESS` or controllable session values | Session file path known; session data partially controllable |
| **pearcmd.php Abuse** | Include `/usr/local/lib/php/pearcmd.php` which parses `$_SERVER['argv']` from query string, allowing arbitrary file creation via `config-create` or `install` commands | PEAR/PECL installed (common in Docker images); `register_argc_argv=On` |
| **register_argc_argv Path Manipulation** | When `register_argc_argv=On` (enabled by default in PHP CLI and many php.ini distributions including Docker images), PHP populates `$_SERVER['argv']` by parsing the query string on `=` and `+` delimiters. Any PHP script that reads `$_SERVER['argv']` — not just pearcmd.php — becomes exploitable via web requests. Attacker crafts query strings that inject arbitrary arguments into scripts designed for CLI execution but accessible via web (e.g., `?+-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input`) | `register_argc_argv=On`; target PHP script reads `$_SERVER['argv']` or uses `getopt()`; script reachable via web request |
| **Craft CMS register_argc_argv RCE** | Craft CMS exposes PHP initialization scripts (e.g., `index.php`, `queue/run`) that are accessible via web and invoke Yii console commands parsing `$_SERVER['argv']`. Attacker injects `-d` flags via query string to override PHP INI directives at runtime — enabling `allow_url_include` and setting `auto_prepend_file=php://input` — achieving unauthenticated RCE without file upload or shell access | Craft CMS installation; `register_argc_argv=On` (default); Craft entry script reachable via web |
| **Temporary Upload File** | PHP creates temp files for uploads (`/tmp/phpXXXXXX`); race condition to include the temp file before it's deleted | Predictable temp path + race window |
| **/proc/self/environ** | Include `/proc/self/environ` where User-Agent header is reflected, containing injected PHP code | Linux; `proc` filesystem accessible |
| **phpinfo() + LFI Race** | phpinfo() displays temporary file paths for current uploads; race condition to include the file before cleanup | phpinfo() page accessible + LFI |

---

## §4. Dynamic Code Evaluation

PHP provides numerous functions and language constructs that evaluate strings as code at runtime. When user input reaches these sinks — directly or through intermediate transformations — arbitrary code execution results.

### §4-1. Direct Evaluation Functions

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **eval()** | Evaluates a string as PHP code; `eval($_GET['code'])` is direct RCE | User input reaches eval() argument |
| **assert()** | `assert()` evaluates its argument as PHP code if it's a string, identical to `eval()`. String evaluation was deprecated in PHP 7.2 and **removed in PHP 8.0**. | PHP < 8.0 (string eval works through 7.x); deprecated warning in PHP 7.2+ |
| **create_function()** | Internally uses `eval()` to create anonymous functions; code injection in the function body parameter achieves RCE | Deprecated in PHP 7.2; removed in PHP 8.0 |
| **preg_replace() /e Modifier** | The `/e` modifier causes the replacement string to be evaluated as PHP code after regex substitution | Deprecated in PHP 5.5; removed in PHP 7.0 |

### §4-2. Command Execution Functions

PHP provides direct OS command execution through multiple functions, each with subtly different behavior.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **system()** | Executes command, outputs result directly to browser | Not in `disable_functions` |
| **exec()** | Executes command, returns last line of output | Not in `disable_functions` |
| **shell_exec() / backticks** | Executes via shell, returns full output; backtick operator `` `cmd` `` is syntactic sugar for `shell_exec()` | Not in `disable_functions` |
| **passthru()** | Executes command, passes raw binary output to browser (useful for image generation) | Not in `disable_functions` |
| **popen() / proc_open()** | Opens a process handle for read/write interaction; `proc_open()` provides stdin/stdout/stderr control | Not in `disable_functions` |
| **pcntl_exec()** | Replaces the current process with the executed program; no shell interpretation (safest, but still dangerous) | `pcntl` extension loaded |

### §4-3. Indirect Code Execution

Functions that don't obviously execute code but can be weaponized to achieve it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **usort() / uasort() / uksort()** | Accept callable as comparison function; if the callable is user-controlled, arbitrary functions can be invoked: `usort($arr, $_GET['func'])` | User controls callable parameter |
| **array_map() / array_filter() / array_walk()** | Similarly accept callables; `array_map($_GET['f'], [$_GET['arg']])` calls any function with controlled arguments | User controls callable parameter |
| **call_user_func() / call_user_func_array()** | Directly invokes any callable: `call_user_func($_GET['f'], $_GET['a'])` | User controls function name and/or arguments |
| **Reflection API** | `ReflectionFunction`, `ReflectionMethod` can invoke arbitrary functions/methods | User controls class/method names |
| **Variable Functions** | `$func = $_GET['f']; $func();` — PHP evaluates the variable as a function name | User controls variable used as function name |

### §4-4. File-Based Code Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **auto_prepend_file / auto_append_file** | PHP configuration directives that include a specified file before/after every script execution; controllable via `.user.ini` or `.htaccess` | Attacker can upload `.user.ini` to web-accessible directory |
| **.user.ini Injection** | Upload a `.user.ini` file setting `auto_prepend_file=uploaded_image.jpg` where the image contains embedded PHP code | File upload to directory with PHP handler; CGI/FastCGI mode |
| **.htaccess Injection** | Upload `.htaccess` with `php_value auto_prepend_file /path/to/shell` or `AddType application/x-httpd-php .jpg` | Apache + mod_php; file upload capability |
| **OPcache File Cache Overwrite** | When `opcache.file_cache` is configured, PHP stores compiled bytecode on disk. Attacker replaces a cached opcode file with a crafted binary payload; the next request to that script executes malicious bytecode, bypassing source-level webshell detection | `opcache.file_cache` enabled; attacker has arbitrary file write to cache directory |
| **Environment Variable auto_prepend_file** | On PHP-CGI/FastCGI deployments where environment variables are controllable (e.g., via HTTP headers mapped to env vars), setting `PHP_VALUE=auto_prepend_file=php://input` causes PHP to execute the POST body before every script — achieving fileless RCE without any file write (CVE-2023-36845, Juniper J-Web) | PHP-CGI/FastCGI; environment variables settable via HTTP request; `allow_url_include` not required when using `php://input` via env var injection |

---

## §5. Configuration & Runtime Sandbox

PHP provides security restrictions (`disable_functions`, `open_basedir`, `safe_mode`) that can be bypassed through various techniques, effectively escaping the PHP sandbox.

### §5-1. disable_functions Bypass

The `disable_functions` directive prevents specific PHP functions from being called. Multiple techniques circumvent this restriction.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LD_PRELOAD + mail()** | `putenv("LD_PRELOAD=/tmp/evil.so")` sets a library preload; `mail()` invokes `/usr/sbin/sendmail` which loads the malicious shared object | `putenv()` and `mail()` not disabled; Linux |
| **LD_PRELOAD + mb_send_mail()** | Same technique using `mb_send_mail()` when `mail()` is disabled | `putenv()` and `mb_send_mail()` not disabled |
| **LD_PRELOAD + imap_mail()** | Same technique using `imap_mail()` as the trigger | `imap` extension loaded; `putenv()` not disabled |
| **LD_PRELOAD + error_log()** | `error_log()` with `message_type=1` (email) invokes sendmail, triggering LD_PRELOAD | `putenv()` and `error_log()` not disabled |
| **PHP-FPM/FastCGI Abuse** | If PHP-FPM is accessible (commonly on port 9000), craft raw FastCGI packets setting `PHP_VALUE` to override `open_basedir` (but not `disable_functions`) and `SCRIPT_FILENAME` to execute arbitrary PHP files | PHP-FPM socket/port accessible |
| **PHP-FPM PATH_INFO Buffer Underflow (CVE-2019-11043)** | When Nginx passes URIs containing `%0a` (newline) to PHP-FPM with `fastcgi_split_path_info`, the regex fails and `env_path_info` becomes empty. The buffer offset calculation `path_info = env_path_info + pilen - slen` underflows, writing a null byte before the intended buffer. This corrupts `fcgi_data_seg->pos`, causing subsequent `FCGI_PUTENV` calls to overwrite existing environment entries. An attacker forges an HTTP header (e.g., `HTTP_EBUT`) whose hash collides with `PHP_VALUE`, injecting `auto_prepend_file=php://input` for RCE | Nginx with `fastcgi_split_path_info`; no `try_files` or file existence check; PHP-FPM ≤ 7.3.10 / 7.2.23 |
| **FFI (Foreign Function Interface)** | PHP 7.4+ FFI allows calling C functions directly: `FFI::cdef("int system(const char*)")->system("id")` | `ffi.enable=true`; FFI extension loaded |
| **ImageMagick / Ghostscript** | If ImageMagick processes user images and Ghostscript is installed, specially crafted images can trigger command execution through Ghostscript's PostScript interpreter | ImageMagick + Ghostscript installed; image processing from user input |
| **iconv/glibc Exploitation (CVE-2024-2961)** | Buffer overflow in glibc's iconv() when converting to ISO-2022-CN-EXT; exploitable through PHP's iconv extension or filter chains to achieve RCE | glibc < 2.40; PHP compiled with iconv |
| **Shellshock (Legacy)** | If bash is vulnerable to Shellshock, `putenv()` + `mail()` can inject commands through bash function definitions in environment variables | Unpatched bash (CVE-2014-6271) |

### §5-2. open_basedir Bypass

`open_basedir` restricts PHP file operations to specified directory trees. Multiple techniques break this restriction.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **glob:// Protocol** | `glob://` wrapper can list directory contents outside `open_basedir` | Works on most PHP versions |
| **FastCGI PHP_VALUE Override** | PHP-FPM `PHP_VALUE` can override `open_basedir` (unlike `disable_functions`) | PHP-FPM accessible |
| **SplFileInfo::getRealPath()** | Certain SPL methods leak real paths of files outside `open_basedir` through error messages | Version-dependent |
| **ini_set() Narrowing** | `ini_set('open_basedir', '..')` can narrow but sometimes escape the restriction through relative path resolution | Specific PHP versions |
| **Symlink Race** | Create a symlink inside `open_basedir` pointing outside; race between symlink creation and the check | Writable directory within `open_basedir` |

---

## §6. Variable Manipulation & Scope Pollution

PHP provides several mechanisms for dynamically creating or overwriting variables from external input, enabling attackers to corrupt application state.

### §6-1. Variable Overwrite Functions

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **extract()** | `extract($_POST)` creates variables from array keys; `$_POST['is_admin'] = 1` creates `$is_admin = 1`, overwriting existing variables | `extract()` called on user input without `EXTR_SKIP` |
| **extract() Memory Corruption** | CVE affecting PHP 5.x–8.x where `extract()` on crafted arrays triggers double-free or use-after-free conditions | Specific PHP versions; attacker-controlled array structure |
| **parse_str()** | `parse_str($_SERVER['QUERY_STRING'])` without second parameter creates variables in current scope from query string parameters | `parse_str()` without second argument (deprecated in PHP 7.2) |
| **mb_parse_str()** | Multibyte version of `parse_str()` with identical variable overwrite behavior | Same conditions as `parse_str()` |
| **import_request_variables()** | Directly imports GET/POST/Cookie into global scope | Removed in PHP 5.4 |
| **register_globals** | Global PHP configuration that automatically creates variables from all input sources (GET, POST, Cookie, Server) | Removed in PHP 5.4; historically devastating |

### §6-2. Variable Variable Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **$$variable Injection** | `$$key = $value` in a loop over user input creates/overwrites arbitrary variables: `foreach($_GET as $k => $v) { $$k = $v; }` | Variable variables with user-controlled names |
| **Compact/Extract Round-trip** | `compact()` and `extract()` round-trips can introduce unexpected variables if array keys are manipulated between operations | Complex variable manipulation patterns |

### §6-3. PHP Query String Parser Quirks

PHP's query string parser has unique normalization behavior that differs from other languages, creating bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dot-to-Underscore Conversion** | PHP converts `.` to `_` in parameter names: `user.name` becomes `user_name` | WAF rules checking original parameter names |
| **Space-to-Underscore Conversion** | Spaces in parameter names are converted to `_` | WAF bypass scenarios |
| **Bracket Parsing** | `param[key]=value` creates arrays; `param[][]=value` creates nested arrays; can cause unexpected application behavior | Complex parameter structures |
| **Duplicate Parameter Handling** | PHP takes the **last** value for duplicate parameters (`?a=1&a=2` → `a=2`), while many proxies/WAFs take the first | Proxy/WAF differential parsing |

---

## §7. Input Validation & Filtering Weaknesses

PHP's built-in validation and filtering functions contain design flaws and implementation bugs that produce false positives, allowing malicious input to pass security checks.

### §7-1. filter_var() Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **FILTER_VALIDATE_URL JavaScript Bypass** | `filter_var("javascript://comment%0aalert(1)", FILTER_VALIDATE_URL)` returns `true`; the `//` is treated as a valid authority component, and `%0a` introduces a newline separating JS code | URL validation used for XSS prevention |
| **FILTER_VALIDATE_URL IPv6 Early Return** | For HTTP-IPv6 URLs, an early return skips user_info validation, allowing invalid username:password combinations to pass | IPv6 URL validation |
| **FILTER_VALIDATE_EMAIL SQL Injection** | `'||1#@i.i` passes FILTER_VALIDATE_EMAIL and FILTER_SANITIZE_EMAIL while containing SQL injection payload | Email validation used as SQL injection defense |
| **FILTER_VALIDATE_URL Integer Wraparound** | Integer overflow in URL length calculation bypasses filtering logic | Extremely long URL input |

### §7-2. Null Byte & Encoding Tricks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Null Byte in fsockopen()** | `fsockopen("localhost\0.safedomain.com")` can be interpreted differently from validation helpers such as `parse_url()`, creating SSRF / allowlist bypass or DoS risk (CVE-2025-1220) | PHP branch-specific affected ranges, including 8.1.x < 8.1.33, 8.2.x < 8.2.29, 8.3.x < 8.3.23, 8.4.x < 8.4.10; hostname validation via parse_url() |
| **gethostbyname() Null Truncation** | `gethostbyname()` silently truncates hostnames at null bytes, creating SSRF opportunities | Hostname validation before DNS resolution |
| **parse_url() vs. curl Differential** | `parse_url()` and `curl_exec()` parse URLs differently (different RFC compliance), enabling SSRF through parser differentials | URL validation via parse_url(), request via curl |
| **Multibyte Encoding Exploits** | Incomplete multibyte sequences in Shift-JIS, GBK, and similar encodings can "eat" escape characters, bypassing security filters | Application using multibyte character sets |
| **mbstring Function Inconsistency** | PHP's `mbstring` extension functions (`mb_strpos()`, `mb_substr()`, `mb_strtolower()`, `mb_ereg()`) interpret byte sequences differently than their single-byte counterparts (`strpos()`, `substr()`, `strtolower()`, `preg_match()`). When a security sanitizer uses mbstring-aware functions but subsequent processing uses single-byte functions (or vice versa), character boundary misalignment creates bypass opportunities — a multi-byte character partially consumed by one function causes remaining bytes to be reinterpreted, smuggling payloads past the sanitizer | Application mixes mbstring and standard string functions in security-critical code paths; input contains multi-byte encodings (UTF-8, Shift-JIS, EUC-JP, Big5) where encoding-aware and encoding-unaware processing are chained |

### §7-3. Path & Filename Validation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Windows Best-Fit Mapping** | Windows "Best-Fit" encoding converts soft hyphens (0xAD) to real hyphens, bypassing PHP-CGI argument filtering (CVE-2024-4577) | Windows + PHP-CGI + specific code pages |
| **Path Truncation** | Paths > 4096 bytes are silently truncated, dropping appended extensions | PHP < 5.3; Linux/Mac |
| **Double Encoding** | `%252e%252e%252f` decoded once yields `%2e%2e%2f`, then `../` | Application performs redundant URL decoding |
| **Windows ADS** | `file.php::$DATA` accesses the file's default data stream on NTFS, sometimes bypassing extension checks | Windows + NTFS filesystem |
| **Case Sensitivity Differential** | `FILE.PHP` and `file.php` refer to the same file on Windows but different files on Linux; exploitable for filter bypass | Cross-platform deployment differences |

### §7-4. ReDoS as Validation Bypass

Regular expression denial of service (ReDoS) via catastrophic backtracking can be weaponized not merely for DoS, but as a **security check bypass**: when a regex-based safety validation times out or exceeds PCRE backtracking limits, `preg_match()` returns `false` (error) instead of `0` (no match) or `1` (match). If the application does not distinguish error from no-match, the safety check is silently skipped.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PCRE Backtracking Limit Bypass** | Crafting input that causes `preg_match()` to exceed `pcre.backtrack_limit` (default 1,000,000). The function returns `false`, which may be loosely compared as falsy (equivalent to "no dangerous pattern found"), allowing malicious input through the validation gate. This was demonstrated against MyBB's template engine safety check (CVE-2023-41362), where bypassing the regex validation enabled code injection into templates leading to RCE | `preg_match()` return value checked with loose comparison (`if (!preg_match(...))`); input length/complexity sufficient to trigger backtracking limit |

---

## §8. Memory Safety & Interpreter Bugs

PHP is implemented in C, and bugs in the interpreter itself — buffer overflows, use-after-free, integer overflows — can be exploited for RCE, DoS, or information disclosure even without application-level vulnerabilities.

### §8-1. Heap & Buffer Overflow

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **array_merge() Integer Overflow (CVE-2025-14178)** | When total element count of packed arrays exceeds 32-bit limits, integer overflow in `zend_hash_num_elements()` precomputation causes heap buffer overflow | PHP 7.1–8.5 (before patches); very large arrays |
| **iconv() Buffer Overflow (CVE-2024-2961)** | glibc's `iconv()` overflows when converting to ISO-2022-CN-EXT charset; exploitable through PHP's iconv extension and filter chains | glibc < 2.40; expert exploitation through PHP heap manipulation |
| **ldap_escape() Overflow** | Uncontrolled long string input to `ldap_escape()` on 32-bit systems causes integer overflow → out-of-bounds write | 32-bit PHP; LDAP extension |
| **json_decode() Buffer Overflow** | `JSON_INVALID_UTF8_IGNORE` or `JSON_INVALID_UTF8_SUBSTITUTE` flags can trigger buffer overflow with crafted UTF-8 sequences | Specific PHP versions with JSON flags |

### §8-2. Use-After-Free

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **__set + ??= Operator** | Code sequence involving `__set` handler combined with `??=` operator and exceptions leads to use-after-free | PHP 8.3/8.4 (before patches); specific OOP patterns |
| **SplDoublyLinkedList** | Iterator invalidation during linked list traversal when elements are removed during iteration | Specific PHP versions; iterator manipulation |
| **unserialize() UAF** | Crafted serialized strings can trigger use-after-free during deserialization of complex object graphs | Multiple historical CVEs across PHP versions |

### §8-3. CGI Argument Injection (CVE-2024-4577)

This vulnerability deserves special attention due to its critical severity (CVSS 9.8) and mass exploitation in 2024–2025.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Best-Fit Character Injection** | Windows Best-Fit encoding converts Unicode soft hyphen (0xAD) to ASCII hyphen (0x2D), which PHP-CGI interprets as a command-line option flag (`-d`, `-r`, etc.) | Windows + Apache + PHP-CGI; any Windows code page with Best-Fit mapping |
| **Argument Payload: auto_prepend** | `-d allow_url_include=1 -d auto_prepend_file=php://input` causes PHP to execute POST body as PHP code | CVE-2024-4577 exploitable configuration |
| **Argument Payload: Direct Execution** | `-r <code>` directly executes PHP code provided as argument | CVE-2024-4577 with `-r` flag injection |

This vulnerability is actively exploited at scale, with 1,089+ unique attacking IPs detected in January 2025 alone, delivering ransomware, Quasar RAT, and XMRig miners.

---

## §9. Cryptographic & Randomness Weaknesses

PHP's historical random number generators and cryptographic primitives contain predictability flaws that compromise tokens, sessions, and secrets.

### §9-1. PRNG Predictability

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **mt_rand() Seed Recovery** | With sufficient consecutive outputs (~624 untempered 32-bit values), the MT19937 internal state can be recovered algebraically via matrix inversion over GF(2). With only a few outputs, the practical approach is brute-forcing the 32-bit seed space (see below). | Application leaks mt_rand() outputs (e.g., in tokens, IDs) |
| **mt_rand() Seed Bruteforce** | The 32-bit seed space can be exhaustively searched in under 60 seconds on modern hardware; tool: `php_mt_seed` | Any single mt_rand() output is known |
| **rand() LCG Prediction** | PHP's `rand()` uses a Linear Congruential Generator with known parameters; state is recoverable from sequential outputs | Application leaks rand() outputs |
| **Session ID Entropy Leakage** | PHP session IDs may leak entropy from the internal LCG seed; recovered seed enables prediction of other random values in the same process | Session ID observable + mt_rand() used for security tokens |
| **uniqid() Predictability** | `uniqid()` is based on `gettimeofday()` with optional entropy; without `more_entropy=true`, output is trivially predictable from server time | `uniqid()` used for security-sensitive identifiers |

### §9-2. Cryptographic Misuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **hash_equals() vs. == for HMAC** | Using `==` to compare HMACs enables timing attacks and type juggling; `hash_equals()` is timing-safe but only available since PHP 5.6 | HMAC comparison with `==` |
| **mcrypt Weakness** | `mcrypt` extension (removed in PHP 7.2) had ECB mode as default, no built-in authentication, and used zero-padding | Legacy applications still using mcrypt |
| **openssl_random_pseudo_bytes() Flag** | The `$crypto_strong` output parameter may be `false` indicating non-cryptographic randomness was used; often ignored by developers | Failure to check `$crypto_strong` flag |
| **password_hash() Truncation** | `PASSWORD_BCRYPT` silently truncates passwords at 72 bytes; passwords longer than 72 bytes that share the first 72 bytes will compare as identical | Very long passwords with bcrypt |

---

## §10. XML Processing

PHP's XML processing extensions expose standard XXE attack vectors, with PHP-specific nuances in configuration and mitigation.

### §10-1. XML External Entity Injection (XXE)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SimpleXML XXE** | `simplexml_load_string()` with default settings (PHP < 8.0 with libxml < 2.9) loads external entities, enabling file read, SSRF, and DoS | PHP < 8.0 with libxml < 2.9; or explicit `LIBXML_NOENT` flag |
| **DOMDocument XXE** | `DOMDocument::loadXML()` with `LIBXML_NOENT` or old libxml versions processes external entities | Explicit entity substitution enabled |
| **XMLReader XXE** | `XMLReader::read()` can process external entities during streaming XML parsing | Old libxml or misconfigured parser |
| **SimpleXML Billion Laughs** | Recursive entity expansion (XML bomb) causes exponential memory consumption → DoS | Entity expansion not limited |
| **LIBXML_NO_XXE Flag** | PHP 8.4 introduced `LIBXML_NO_XXE` constant (requires libxml >= 2.13.0) as explicit XXE prevention | PHP 8.4+; explicit opt-in required |

libxml2 >= 2.9.0 (shipped with PHP 8.0+) disables external entity loading by default, significantly reducing the XXE surface. However, applications explicitly enabling `LIBXML_NOENT` or `LIBXML_DTDLOAD` remain vulnerable.

---

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Remote Code Execution** | PHP-CGI on Windows; unserialize() reachable; LFI + writable path; eval() with user input | §2 + §3 + §4 + §5-1 + §8-3 |
| **Authentication Bypass** | Loose comparison on credentials/tokens; type juggling via JSON input | §1-1 + §1-2 + §1-3 |
| **Arbitrary File Read** | LFI with php://filter; XXE with entity loading; SSRF to file:// | §3-2 + §7-2 + §10-1 |
| **Server-Side Request Forgery** | parse_url()/fsockopen() differential; filter_var() bypass; XXE | §7-1 + §7-2 + §10-1 |
| **Sandbox Escape** | LD_PRELOAD + mail(); FFI; FastCGI abuse; glob:// open_basedir bypass | §5-1 + §5-2 |
| **Denial of Service** | XML bomb; regex catastrophic backtracking; hash collision; large array operations | §8-1 + §10-1 |
| **Variable/State Corruption** | extract(); parse_str(); register_globals (legacy); query parser differential | §6-1 + §6-2 + §6-3 |
| **Token/Session Prediction** | mt_rand() seed recovery; uniqid() prediction; session ID entropy leak | §9-1 |
| **Webshell Deployment** | .user.ini upload + auto_prepend_file; PHAR polyglot upload; file write gadget chain; OPcache file cache overwrite | §2-4 + §4-4 |

---

## §12. CVE / Bounty Mapping (2024–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §8-3 (CGI Argument Injection) | CVE-2024-4577 (PHP-CGI on Windows) | CVSS 9.8. Mass exploitation — 1,089+ IPs in Jan 2025; ransomware, RAT, cryptominer deployment. Affects all PHP versions on Windows before 8.1.29/8.2.20/8.3.8 |
| §8-1 (iconv Buffer Overflow) | CVE-2024-2961 (glibc iconv via PHP) | CVSS 8.8. 24-year-old glibc bug; PHP filter chains convert file read to RCE. Chained with CVE-2024-34102 (Magento) for unauthenticated RCE |
| §2-1 (PHP Object Injection) | CVE-2025-49113 (Roundcube Webmail) | CVSS 9.9. Post-auth RCE via deserialization of _from parameter. Exploit reportedly sold in underground forums shortly after disclosure |
| §2-1 (PHP Object Injection) | CVE-2024-10957 (WordPress UpdraftPlus) | CVSS 8.8. Unauthenticated PHP object injection in UpdraftPlus 1.23.8–1.24.11; impact requires a POP chain from another plugin/theme and administrator search/replace action to trigger |
| §2-1 + §2-4 (Gadget Chain) | GiveWP Plugin CVE (2024) | CVSS 10.0. Unauthenticated POP chain via `give_title` parameter. Public bounty case |
| §8-1 (Heap Overflow) | CVE-2025-14178 (array_merge()) | Heap buffer overflow via integer overflow in element count precomputation. Affects PHP 7.1–8.5 |
| §8-2 (Use-After-Free) | CVE-2024-11235 (`__set` / `??=` + exceptions) | Use-after-free in PHP 8.3.x < 8.3.19 and 8.4.x < 8.4.5; potential RCE if attacker can shape memory layout |
| §7-2 (Null Byte in fsockopen) | CVE-2025-1220 (PHP core) | Null-byte hostname handling in `fsockopen()` and related functions can bypass hostname validation patterns or cause parsing failures; patch per maintained PHP branch |
| §3-3 (Filter Chain Oracle) | CVE-2026-22200 (osTicket) | PHP filter chain injection in rich text fields; server file exfiltration via PDF export |
| §2-2 (PHAR Deserialization) | WP Meta SEO PHAR Deser (2024) | PHAR deserialization → RCE via file operation on attacker-controlled phar:// path |
| §10-1 (XXE) | WordPress 5.7 XXE (Sonar) | XXE in WordPress media library XML parsing |
| §5-1 (PHP-FPM buffer underflow) | CVE-2019-11043 (PHP-FPM) | RCE via PATH_INFO buffer underflow → `fcgi_data_seg->pos` corruption → `PHP_VALUE` hash collision injection. Actively exploited in the wild |

---

## §13. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **PHPGGC** (Ambionics) | §2 — Deserialization gadget chains | Library of pre-built POP chains for 20+ frameworks; generates serialized payloads from CLI |
| **php_mt_seed** (Openwall) | §9-1 — mt_rand() seed recovery | Bruteforces 32-bit mt_rand() seed space in < 60 seconds |
| **Snowflake** (Argyros) | §9-1 — rand()/mt_rand() prediction | Automated seed recovery for rand() and mt_rand() with multiple output samples |
| **php_filter_chains_oracle_exploit** (Synacktiv) | §3-3 — PHP filter chain oracle | Automates character-by-character file exfiltration via error-based oracle on filter chains |
| **Lightyear** (Lexfo) | §3-2 + §3-3 — Filter chain file dump | Optimized filter chain exploitation using iconv conversion sequences; ~6 requests per character |
| **CNEXT Exploits** (Ambionics) | §8-1 — CVE-2024-2961 exploitation | Exploits glibc iconv buffer overflow through PHP filter chains for RCE |
| **Chankro** | §5-1 — disable_functions bypass | Generates PHP scripts exploiting LD_PRELOAD + mail() to execute binaries |
| **dfunc-bypasser** | §5-1 — disable_functions bypass | Enumerates available functions to find bypass paths for disable_functions |
| **LFIHunt** | §3 — LFI scanning and exploitation | Automated LFI scanner with wrapper exploitation and RCE escalation |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Psalm** (Vimeo) | §4 — Taint analysis for code injection | Static analysis with taint tracking; detects user input flowing to dangerous sinks |
| **PHPStan** | General — Type safety analysis | Static analysis enforcing strict typing; catches type juggling patterns (§1) |
| **Snuffleupagus** | §5 — Runtime hardening | PHP module that hardens unserialize(), disables eval(), enforces strict comparison at runtime |
| **RIPS** | §2 + §3 + §4 — PHP-specific SAST | Commercial static analysis specifically designed for PHP security vulnerabilities |
| **SensioLabs Security Checker** | §2-4 — Dependency vulnerabilities | Checks composer.lock for known vulnerable PHP packages (including gadget-chain-capable libraries) |
| **Suhosin** | §5 + §6 — Runtime protection | PHP extension hardening session handling, variable limits, and dangerous function restrictions |
| **TYPO3 Phar Stream Wrapper** | §2-2 — PHAR deserialization prevention | Intercepts phar:// stream wrapper operations to prevent automatic metadata deserialization |

---

## §14. Summary: Core Principles

### The Root Cause

PHP's vulnerability surface is exceptionally broad because of a fundamental architectural tension: **PHP was designed for maximum developer convenience in a dynamically-typed, request-response web context, but this convenience systematically trades away security guarantees.** The loose type system (§1), automatic serialization/deserialization (§2), promiscuous stream wrapper architecture (§3), string-to-code evaluation (§4), and ini-file-based configuration model (§5) each independently create large attack surfaces. When combined — as they routinely are in real exploits — they produce chains of devastating effectiveness.

The type juggling problem (§1) illustrates this perfectly: PHP's `==` operator was designed so that `"42" == 42` would be `true`, saving developers from explicit casting. But this same design means `"0e123" == "0e456"` is also `true` (both are `0` in scientific notation), breaking hash comparisons. The convenience-security tradeoff is structural, not accidental.

### Why Incremental Fixes Fail

PHP has made significant progress with each major version: `register_globals` removed (5.4), `/e` modifier deprecated (5.5) and removed (7.0), `create_function()` deprecated (7.2) and removed (8.0), PHAR auto-deserialization disabled (8.0), string-to-integer coercion fixed (8.0), `LIBXML_NO_XXE` added (8.4). Yet each fix addresses one specific vector while leaving the underlying architectural pattern intact. New variants continually emerge: PHP filter chains (§3-2) turned a 2012-era LFI primitive into 2023-era RCE without any new PHP bug — just creative composition of existing features. CVE-2024-4577 exploited a Windows encoding behavior that had been in the OS for decades, requiring only the recognition that PHP-CGI's argument parsing would interact with it. The attack surface regenerates because PHP's core design principles — dynamic typing, implicit conversion, string-as-code capability, filesystem-as-configuration — remain unchanged.

### Structural Solutions

True mitigation requires abandoning convenience in security-critical code: strict typing (`declare(strict_types=1)`), strict comparison (`===`) everywhere, `json_decode()` instead of `unserialize()` for data exchange, `random_int()`/`random_bytes()` instead of `mt_rand()`, explicit input validation instead of `filter_var()`, and deployment configurations that minimize the exposed function/wrapper surface. Modern frameworks (Laravel, Symfony) encapsulate many of these practices, but the underlying PHP runtime remains a minefield for code that steps outside framework boundaries.

---

## References

- [PHP Official CVE Tracking](https://wiki.php.net/cve)
- [PHPGGC Gadget Chain Library](https://github.com/ambionics/phpggc)
- [PayloadsAllTheThings PHP Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md)
- [PayloadsAllTheThings Type Juggling](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md)
- [HackTricks PHP Tricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp)
- [Synacktiv PHP Filter Chains](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it)
- [Lexfo Lightyear / CNEXT](https://blog.lexfo.fr/lightyear-file-dump.html)
- [Ambionics CVE-2024-2961 Exploits](https://github.com/ambionics/cnext-exploits)
- [php_mt_seed](https://github.com/openwall/php_mt_seed)
- [Watchtowr CVE-2024-4577 Analysis](https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/)
- [PHP Security — Survive The Deep End](https://phpsecurity.readthedocs.io/)
- [Quarkslab Laravel Gadget Chain Research](https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html)
- [Synacktiv PHP Filter Chain Oracle Exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit)
- [Dangerous PHP Functions Reference](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720)
- [GreyNoise CVE-2024-4577 Mass Exploitation Report](https://www.greynoise.io/blog/mass-exploitation-critical-php-cgi-vulnerability-cve-2024-4577)
- Positive Technologies: "Exploiting Arbitrary Object Instantiations in PHP without Custom Classes" (2022) — Systematic exploitation of built-in PHP classes (`SplFileObject`, `SimpleXMLElement`, `GlobIterator`, `Imagick`, `ReflectionFunction`) via `new $class($arg)` patterns

---

*This document was created for defensive security research and vulnerability understanding purposes.*
