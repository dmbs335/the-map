# CI/CD Pipeline Security Mutation Taxonomy

**A Comprehensive Classification of Attack Vectors Across the Continuous Integration and Continuous Deployment Lifecycle**

---

## Classification Structure

This taxonomy organizes CI/CD security vulnerabilities across **three orthogonal axes**:

**Axis 1 (Primary): Attack Surface Component** — The structural layer of the CI/CD pipeline being targeted. This forms the main organizational structure of the document (§1–§8).

**Axis 2 (Cross-Cutting): Attack Mechanism** — The nature of the exploitation technique. These mechanisms apply across multiple components and represent how attackers achieve their objectives.

**Axis 3 (Mapping): Attack Scenario** — The real-world impact and deployment context in which mutations become weaponizable.

### Cross-Cutting Attack Mechanisms (Axis 2)

These mechanisms appear throughout all categories and represent fundamental exploitation patterns:

| Mechanism | Description | Key Characteristic |
|-----------|-------------|-------------------|
| **Code Injection** | Insertion of attacker-controlled code into execution context | Shell commands, expressions, scripts executed by pipeline |
| **Configuration Manipulation** | Modification of pipeline behavior through config changes | Workflow files, CI settings, environment configuration |
| **Authentication Bypass** | Circumventing identity verification mechanisms | Token forgery, session hijacking, credential theft |
| **Supply Chain Poisoning** | Injection of malicious code into trusted dependencies | Package substitution, artifact tampering, transitive attacks |
| **Information Disclosure** | Extraction of sensitive data from pipeline environment | Secrets, credentials, source code, internal architecture |
| **Privilege Escalation** | Gaining elevated permissions within CI/CD system | Token abuse, role manipulation, ACL bypass |
| **Resource Hijacking** | Unauthorized use of CI/CD infrastructure | Crypto mining, C2 infrastructure, compute abuse |
| **Parsing Differential** | Exploiting interpretation differences between components | Configuration parsers, package resolvers, version matchers |

---

## §1. Pipeline Configuration Layer

The pipeline configuration layer defines workflow behavior through YAML, JSON, or domain-specific configuration files. Attackers manipulating this layer can execute arbitrary code within the CI/CD environment.

### §1-1. Direct Configuration Injection

Attackers with repository write access directly modify CI/CD configuration files to inject malicious commands.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Branch Push Injection** | Push malicious workflow changes to unprotected branches that trigger automated builds | Lack of branch protection on branches that trigger CI |
| **Configuration File Replacement** | Completely replace legitimate pipeline config with malicious version | Write access to repository, no approval required |
| **Multi-Stage Payload Insertion** | Insert commands across multiple pipeline stages to evade detection | Complex pipelines with many stages |
| **Conditional Trigger Manipulation** | Modify when/if conditions to execute malicious code under specific circumstances | Event-based triggers (tags, releases, specific branches) |

**Direct PPE (Poisoned Pipeline Execution)** occurs when an attacker modifies `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, or similar configuration files in a repository they have access to. The malicious workflow executes when triggered by push or pull request events.

### §1-2. Indirect Configuration Injection

Malicious code is injected into files *referenced by* the configuration rather than the configuration itself.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Script File Poisoning** | Modify shell scripts, Python files, or other executables called by workflow | Configuration executes external scripts without integrity checks |
| **Makefile/Build Script Injection** | Insert malicious commands into build automation files | Pipeline delegates to build tools (make, npm scripts, gradle) |
| **Docker/Container File Manipulation** | Modify Dockerfile or container build instructions | Pipeline builds containers from repository-defined files |
| **Test Harness Injection** | Insert malicious code into test files that execute during CI | Test execution lacks sandboxing |

**Indirect PPE (I-PPE)** operates by modifying files like `build.sh`, `package.json` scripts, or test files that are invoked by the unchanged CI configuration.

### §1-3. Pull Request Configuration Injection

Attackers without direct write access use pull requests to propose malicious configuration changes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Public PPE (3PE)** | Submit PR from fork in public repo; CI runs unreviewed code | `pull_request_target`, `workflow_run`, or unrestricted PR triggers |
| **Maintainer Impersonation** | Craft legitimate-looking PRs that trick maintainers into approving malicious workflows | Social engineering + workflow complexity |
| **Approval Bypass via Race Condition** | Submit benign PR, get approval, then force-push malicious version before merge | Time gap between approval and merge |
| **Nested PR Trigger Chain** | Create PR that modifies workflow to trigger on future PRs, creating persistent backdoor | Workflows that modify themselves |

The `pull_request_target` trigger in GitHub Actions is particularly dangerous as it executes with repository secrets and write permissions even for PRs from untrusted forks.

---

## §2. Source Control Layer

Source control systems (Git, SVN, Mercurial) manage code versioning. Attackers targeting this layer manipulate repository state to trigger malicious pipelines or poison the codebase.

### §2-1. Branch and Tag Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tag Retargeting Attack** | Modify existing Git tags to point to malicious commits | Mutable tags, CI triggered by tag events |
| **Protected Branch Bypass via Actions** | Use GitHub Actions token permissions to push directly to protected branches | Actions granted bypass permissions |
| **Branch Name Injection** | Create branches with names containing shell metacharacters that get interpolated | Workflow uses `github.head_ref` or similar in shell context |
| **Orphan Branch Trigger** | Create disconnected branch to trigger CI without appearing in normal commit history | CI triggers on all branch pushes |
| **Release Hijacking** | Create malicious release tags to distribute trojanized artifacts | Automated release process on tag creation |

**Tag Retargeting** was weaponized in the March 2025 tj-actions/changed-files compromise, where attackers retroactively modified version tags (v1, v2, etc.) to reference a malicious commit, affecting 23,000+ repositories.

### §2-2. Commit and History Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rebase Injection** | Insert malicious commits via interactive rebase after PR approval | Time window between approval and merge |
| **Submodule Poisoning** | Point Git submodules to attacker-controlled repositories | Submodules updated without review |
| **`.git` Directory Exploitation** | Manipulate Git metadata to hide malicious commits or bypass controls | Direct filesystem access to `.git` |
| **Signed Commit Spoofing** | Forge commit signatures to appear as trusted maintainers | GPG key compromise or validation bypass |

### §2-3. Pull Request and Review Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Self-Approval Exploit** | Approve own pull requests when repository settings allow | Inadequate access controls (OWASP CICD-SEC-1) |
| **Required Review Bypass** | Leverage GitHub Actions to push code without required reviews | GitHub App tokens with bypass permissions |
| **CODEOWNERS Bypass** | Modify code protected by CODEOWNERS without required owner approval | CODEOWNERS validation not enforced |
| **Approval State Hijacking** | Modify PR content after receiving approvals | No re-approval required on push after approval |

---

## §3. Secrets & Credentials Layer

CI/CD pipelines require access to sensitive credentials for deployment, API access, and third-party integrations. This layer is a primary target for information disclosure attacks.

### §3-1. Direct Secrets Extraction

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Environment Variable Dumping** | Print `env`, `printenv`, or access `process.env` to expose secrets | Attacker controls executed code |
| **Context Variable Exfiltration** | Access GitHub Actions `secrets.*` or GitLab `CI_*` variables | Expression injection or script access |
| **Log-Based Exfiltration** | Echo secrets to CI logs, which are publicly accessible | Public repository with public workflow logs |
| **File-Based Secret Discovery** | Read secrets from mounted volumes, temp files, or filesystem | Secrets materialized as files (kubeconfig, service accounts) |

The tj-actions/changed-files compromise (CVE-2025-30066) extracted secrets from Runner Worker process memory and printed them to GitHub Actions logs, exposing AWS keys, GitHub PATs, npm tokens, and RSA keys.

### §3-2. Secrets Management Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Masked Output Bypass** | Use encoding (base64, hex) or obfuscation to bypass secret masking in logs | CI secret masking based on exact string match |
| **Secret Injection via External Process** | Access secrets through child processes that don't inherit masking | Secrets available to all child processes |
| **Cache-Based Secret Persistence** | Write secrets to CI cache to access in future runs | Unrestricted cache write access |
| **Artifact Upload with Secrets** | Bundle secrets into build artifacts uploaded to public storage | No artifact content validation |

### §3-3. Credential Theft from Memory and Runtime

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Process Memory Scraping** | Scan runner process memory for credentials and tokens | Arbitrary code execution on runner |
| **Environment Inheritance** | Capture secrets from parent process environment | Pipeline spawns child processes with full env |
| **Token File Extraction** | Read GitHub Actions token from `GITHUB_TOKEN` file or credential helpers | Filesystem access to token storage locations |
| **SSH Agent Hijacking** | Extract SSH keys from ssh-agent running in CI environment | SSH agent forwarding enabled |

### §3-4. OIDC and Federated Identity Abuse

OpenID Connect (OIDC) allows CI/CD systems to obtain cloud credentials without long-lived secrets.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **OIDC Claim Injection** | Manipulate workflow attributes (branch name, environment) that become OIDC claims | Claims derived from user-controlled inputs |
| **Trust Policy Overpermissioning** | Exploit overly broad OIDC trust policies that accept tokens from any repository | AWS trust policy allows `*` in subject claim |
| **OIDC Token Replay** | Capture and reuse OIDC token outside CI environment | Long token expiration, no audience validation |
| **Fork Workflow OIDC Escalation** | Obtain OIDC token from fork PR that grants access to parent repo resources | OIDC federation trusts fork workflows |

The "OH-MY-DC" research (DEF CON 32, 2024) demonstrated how combining PPE with lax OIDC policies allows privilege escalation across cloud environments.

---

## §4. Dependency Resolution Layer

Modern applications depend on hundreds of external packages. The dependency layer is vulnerable to supply chain poisoning through package substitution and malicious dependency injection.

### §4-1. Dependency Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Internal Package Name Squatting** | Register public package with same name as internal private package | Package manager prefers public registry or version number |
| **Namespace Confusion** | Exploit ambiguous namespaces across package ecosystems (npm scopes, PyPI) | Unclear package resolution precedence |
| **Typosquatting** | Register packages with similar names to popular dependencies | Developers make typos in dependency declarations |
| **Version Precedence Exploitation** | Publish higher version number on public registry to override private package | Highest version wins regardless of registry |

**Dependency confusion** exploits package manager resolution order. If `@internal/package` exists in a private registry and `@internal/package` version 999.999.999 is published to npm, the public version may be installed. Up to 49% of organizations have vulnerable assets.

### §4-2. Direct Dependency Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Account Takeover** | Compromise maintainer account and publish malicious version | Weak 2FA, credential reuse, phishing |
| **Malicious Package Publication** | Intentionally publish malicious package for specific targets | Open package registries (npm, PyPI, RubyGems) |
| **Package Lifecycle Hooks** | Abuse `preinstall`, `postinstall`, or similar hooks to execute code | Package managers execute lifecycle scripts |
| **Legitimate Package Trojanization** | Add malicious code to previously benign package | Maintainer account compromise or insider threat |

The **Shai-Hulud 2.0** campaign (November 2025) exploited npm `preinstall` lifecycle scripts, executing malicious payloads even when installation failed, compromising 25,000+ repositories.

### §4-3. Transitive Dependency Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Deep Dependency Injection** | Compromise low-level transitive dependency several layers deep | Limited scrutiny of transitive dependencies |
| **Dependency Update Hijacking** | Publish malicious update to transitive dependency | Automated dependency updates, no lock file |
| **Peer Dependency Confusion** | Manipulate peer dependency resolution to inject malicious package | Complex peer dependency trees |
| **Optional Dependency Exploitation** | Inject malicious code via optional or development dependencies | Dev dependencies installed in CI environment |

### §4-4. Registry and Repository Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mirror Poisoning** | Compromise package registry mirrors used by CI/CD | CI configured to use untrusted mirrors |
| **CDN Cache Poisoning** | Serve malicious package from CDN cache | CDN caching without integrity verification |
| **Registry Misconfiguration** | Exploit exposed package registries with upload permissions | 2,100+ artifact registries found with upload access (2023) |
| **Lockfile Bypass** | Modify dependency versions despite presence of lockfile | CI ignores lockfile or regenerates on build |

---

## §5. Identity & Access Control Layer

CI/CD systems integrate with identity providers and manage permissions for repositories, pipelines, and cloud resources. This layer governs authentication and authorization.

### §5-1. Authentication Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SAML Response Forgery** | Forge SAML assertions to gain unauthorized access | Signature validation bypass (CVE-2024-4985) |
| **OAuth Token Theft** | Steal OAuth tokens from CI logs, artifacts, or process memory | OAuth tokens exposed in CI environment |
| **API Token Leakage** | Extract API tokens from public repositories, container images, logs | Hardcoded tokens in code or configuration |
| **Session Hijacking** | Capture and reuse session cookies or tokens | Long-lived sessions, no IP binding |

**CVE-2024-4985** (GitHub Enterprise Server) enabled unauthenticated attackers to forge SAML responses and gain site administrator access, compromising all repositories, secrets, and CI/CD pipelines.

### §5-2. Authorization and Permission Escalation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **RBAC Bypass** | Exploit inconsistent role-based access control enforcement | Permissions not validated consistently |
| **Pipeline-Based Access Control (PBAC) Abuse** | Leverage pipeline permissions to access resources beyond intended scope | Over-permissioned service accounts (OWASP CICD-SEC-5) |
| **Token Scope Escalation** | Use read-only token to perform write operations | Insufficient scope validation (CVE-2024-8114) |
| **Cross-Repository Permission Leakage** | Access secrets or resources from other repositories in same org | Org-level runners or shared resources |

### §5-3. Service Account and Machine Identity Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Service Account Key Extraction** | Steal GCP/AWS service account keys from CI environment | Keys materialized as files or environment variables |
| **IAM Role Assumption** | Assume AWS/Azure IAM roles granted to CI/CD system | Overly permissive assume-role policies |
| **Managed Identity Abuse** | Leverage Azure Managed Identity or AWS instance profiles | CI runs on VMs with attached identities |
| **Certificate-Based Auth Theft** | Extract client certificates used for authentication | Certificates stored on runner filesystem |

---

## §6. Artifact Management Layer

Build artifacts (container images, packages, binaries) are produced by CI and consumed by CD. This layer is critical for supply chain integrity.

### §6-1. Artifact Substitution and Tampering

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Build Artifact Replacement** | Replace legitimate artifact with malicious version between build and deploy | No artifact signing or integrity verification |
| **Container Image Tag Mutation** | Modify `latest` or version tags to point to malicious images | Mutable image tags in container registry |
| **Package Registry Poisoning** | Upload malicious artifacts to internal package registry | Weak registry authentication (default passwords) |
| **Artifact Metadata Manipulation** | Modify artifact metadata (SBOMs, signatures) without changing content | Metadata stored separately from artifact |

250 million artifacts exposed via misconfigured registries (2023), with 2,100+ registries having upload permissions allowing artifact poisoning.

### §6-2. Registry Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default Credentials** | Access registries using default admin passwords | Unchanged default credentials (57 registries found) |
| **Anonymous Upload Access** | Push malicious artifacts to registries allowing anonymous uploads | Public write access enabled |
| **API Key Leakage** | Discover registry API keys in public repositories or logs | Hardcoded registry credentials |
| **Registry Impersonation** | Point CI to attacker-controlled registry mirror | DNS hijacking or configuration manipulation |

### §6-3. Image and Container Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Base Image Poisoning** | Compromise base images (Alpine, Ubuntu) in private registry | Base images pulled from untrusted sources |
| **Layer Injection** | Insert malicious layers into container images | Multi-stage builds without layer verification |
| **Container Scan Evasion** | Structure malicious code to evade vulnerability scanners | Scanners focus on known CVEs, miss novel malware |
| **Image Squashing Bypass** | Hide malicious content in intermediate layers removed by squashing | Malicious content only in build-time layers |

### §6-4. Software Bill of Materials (SBOM) Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SBOM Falsification** | Generate incorrect SBOM hiding malicious dependencies | SBOM created by compromised build process |
| **SBOM Reconnaissance** | Use publicly available SBOMs to map attack surface | SBOMs published without considering threat modeling |
| **Dependency Mismatch** | Ship different dependencies than declared in SBOM | SBOM generated early in build, not from final artifact |
| **Transitive Dependency Omission** | Omit vulnerable transitive dependencies from SBOM | SBOM tools fail to capture full dependency tree |

---

## §7. Execution Environment Layer

CI/CD jobs execute on runners, agents, or build nodes. Compromising the execution environment enables persistent access and lateral movement.

### §7-1. Runner and Agent Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Self-Hosted Runner Backdoor** | Establish persistence on self-hosted runners across workflow executions | Self-hosted runners not ephemeral |
| **Multi-Repository Runner Contamination** | Compromise org-level runner to access multiple repositories | Runner shared across repositories |
| **Runner Registration Hijacking** | Register malicious runners to receive workflow jobs | Runner registration tokens stolen or predictable |
| **Persistent Malware Installation** | Install malware on runner that survives between jobs | Lack of runner isolation and cleanup |

**Shai-Hulud 2.0** registered infected systems as self-hosted GitHub runners, enabling remote workflow execution and maintaining persistence even after package removal.

### §7-2. Execution Context Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PATH Hijacking** | Prepend malicious directories to PATH to intercept tool execution | Workflow sets PATH without validation |
| **LD_PRELOAD Injection** | Preload malicious shared libraries to hook system calls | Linux runners without LD_PRELOAD restrictions |
| **Tool Binary Replacement** | Replace legitimate build tools (git, npm, docker) with trojanized versions | Tools installed from untrusted sources or writable locations |
| **Compiler Backdoor** | Compromise compiler to inject backdoors into all compiled code | Compiler from untrusted source (supply chain attack) |

### §7-3. Resource Hijacking

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cryptomining Injection** | Execute cryptocurrency miners using CI/CD compute resources | Long-running or unmetered CI jobs |
| **Distributed C2 Infrastructure** | Use compromised runners as command-and-control servers | Runners have outbound internet access |
| **Data Exfiltration Relay** | Proxy stolen data through CI/CD infrastructure to evade detection | CI egress not monitored |
| **Compute Resource Exhaustion** | Execute resource-intensive tasks to cause denial of service | No resource limits on workflow execution |

Ultralytics compromise (December 2024) shipped cryptomining payloads via trojanized GitHub Actions workflow.

### §7-4. Environment-Specific Exploits

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Container Escape** | Break out of containerized CI environment to access host | Privileged containers or kernel vulnerabilities |
| **Kubernetes Pod Compromise** | Exploit CI pods in k8s to access cluster resources | CI pods with service account tokens |
| **Windows Reserved Filename Exploitation** | Use Windows reserved names (CON, PRN, NUL) to bypass security checks | Windows runners with vulnerable code paths |
| **Cloud Metadata Service Access** | Access cloud metadata endpoints (169.254.169.254) from CI | Cloud-hosted runners without metadata restrictions |

---

## §8. Integration & Extension Layer

CI/CD pipelines integrate with third-party actions, webhooks, external APIs, and services. This layer expands the attack surface through untrusted extensions.

### §8-1. Third-Party Action Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious Action Publication** | Publish intentionally malicious GitHub Action or Jenkins plugin | Open action marketplaces |
| **Action Account Takeover** | Compromise action maintainer account and push malicious update | Weak maintainer security |
| **Action Dependency Poisoning** | Inject malicious code into action's dependencies | Actions with complex dependency trees |
| **Action Tag Retargeting** | Modify action version tags to point to malicious code | Mutable tags (v1, v2 vs v1.2.3) |

The tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154) supply chain attacks leveraged tag retargeting to affect 23,000+ repositories.

### §8-2. Expression Language Injection

GitHub Actions and other CI systems use expression languages for dynamic evaluation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Context Variable Injection** | Inject malicious code via `${{ github.event.issue.title }}` or similar | User-controlled data used in expressions |
| **Script Injection via Run Block** | Interpolate untrusted data into shell scripts | `run: echo ${{ github.event.comment.body }}` |
| **Workflow Command Injection** | Inject workflow commands (`::set-output`, `::add-mask`) via expression | Expression output interpreted as workflow commands |
| **Conditional Expression Bypass** | Manipulate if conditions to execute unauthorized code | Complex conditional logic in workflows |

**Multiple GHSL-2024 advisories** (GHSL-2024-050, 051, 057, 145, 277) documented expression injection vulnerabilities allowing repository takeover and secrets theft.

### §8-3. Webhook and Event Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Webhook Replay Attack** | Capture and replay webhook events to trigger unauthorized builds | No webhook signature validation or replay protection |
| **Forged Webhook Events** | Send spoofed webhooks to trigger malicious pipelines | Webhook endpoints publicly accessible, no authentication |
| **Event Data Injection** | Manipulate webhook payload fields used in pipeline logic | Pipeline trusts webhook data without validation |
| **Schedule Trigger Hijacking** | Modify scheduled pipeline triggers to execute malicious code | Scheduled jobs run with elevated permissions |

### §8-4. External Service Integration Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cloud Service Overpermissioning** | Exploit excessive permissions granted to CI for cloud deployments | CI service account has admin/owner permissions |
| **Notification Service Abuse** | Use CI integrations (Slack, email) to exfiltrate data | Outbound notification channels not monitored |
| **Third-Party SaaS Compromise** | Leverage compromised SaaS integrations (Terraform Cloud, Vercel) | CI authenticates to external services with powerful tokens |
| **AI Agent Prompt Injection** | Inject malicious prompts into AI tools integrated with CI/CD | AI agents process untrusted PR/issue content |

**Prompt injection in GitHub Actions** (PromptPwnd research, 2025) demonstrated AI agents connected to CI/CD processing untrusted input and executing shell commands with high-privilege tokens.

---

## Attack Scenario Mapping (Axis 3)

Real-world exploitation combines mutations across multiple components to achieve specific objectives.

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Repository Takeover** | Attacker gains admin control of repository via CI/CD | §1 (PPE) + §2 (Branch Bypass) + §5 (Auth) | Full code control, backdoor insertion |
| **Secrets Exfiltration** | Extract credentials from CI environment to external server | §3 (Secrets) + §7 (Runner) + §8 (Integration) | Cloud account compromise, lateral movement |
| **Supply Chain Compromise** | Inject malicious code into build artifacts distributed to users | §4 (Dependencies) + §6 (Artifacts) + §1 (Pipeline) | End-user compromise, widespread malware distribution |
| **Lateral Movement** | Use CI/CD access to pivot to production or internal networks | §5 (IAM) + §7 (Runner) + §3 (OIDC) | Production system access, data breach |
| **Production Deployment Manipulation** | Modify or sabotage code deployed to production | §1 (Pipeline) + §6 (Artifacts) + §2 (Tags) | Service disruption, backdoor in production |
| **Resource Abuse** | Hijack CI/CD infrastructure for cryptomining or C2 | §7 (Runner) + §1 (Workflow) | Cost increase, infrastructure compromise |
| **Dependency Poisoning at Scale** | Publish malicious package consumed by thousands of projects | §4 (Dependency) + §6 (Registry) | Widespread supply chain impact |
| **OIDC-Based Cloud Compromise** | Leverage OIDC federation to gain cloud access | §5 (OIDC) + §1 (PPE) + §3 (Claims) | AWS/GCP/Azure resource access |
| **Self-Hosted Runner Worm** | Propagate malware across organization via shared runners | §7 (Runner) + §4 (preinstall) + §2 (Repos) | Organization-wide compromise |
| **Cache Poisoning** | Inject malicious content into CI cache to affect future builds | §1 (Workflow) + §7 (Environment) | Persistent backdoor across builds |

---

## CVE / Bug Bounty Mapping (2024-2025)

Real-world incidents demonstrating taxonomy categories.

| Mutation Combination | CVE / Case | Impact / Bounty | Year |
|---------------------|-----------|----------------|------|
| §7-1 + §4-2 + §3-1 | Shai-Hulud 2.0 | 25,000+ repos, self-hosted runner backdoors, mass credential theft | Nov 2025 |
| §8-1 + §3-1 + §2-1 | CVE-2025-30066 (tj-actions/changed-files) | 23,000+ repos, AWS/GitHub/npm token exposure | Mar 2025 |
| §8-1 + §3-1 | CVE-2025-30154 (reviewdog/action-setup) | Cascade attack enabling tj-actions compromise | Mar 2025 |
| §5-1 | CVE-2024-4985 (GitHub Enterprise SAML) | Site admin access, all repos/secrets/CI compromise | 2024 |
| §8-2 | GHSL-2024-050, 051, 057, 145, 277 | Expression injection → repository takeover | 2024 |
| §1-1 + §7-3 + §4-2 | Ultralytics PyPI Compromise | Cryptomining via GitHub Actions, credential exfiltration | Dec 2024 |
| §7-1 | CVE-2024-23897 (Jenkins CLI RCE) | Critical RCE, read arbitrary files, used in ransomware (CVSS 9.8) | Jan 2024 |
| §1-1 + §7-1 | CVE-2025-53652 (Jenkins Git Parameter) | Command injection via Git parameter values | Jul 2025 |
| §1-2 + §3-1 + §6-1 | GhostAction Supply Chain Attack | 327 GitHub users, 817 repos, 3,325 secrets exfiltrated | Sep 2025 |
| §1-1 + §2-1 | CVE-2024-5655, 9164, 6678 (GitLab) | Trigger pipelines as other users, arbitrary branch execution (CVSS 9.6-9.9) | 2024 |
| §4-1 | NX Package npm Compromise | NPM token harvesting during package execution | Aug 2025 |
| §6-1 + §6-2 | Misconfigured Registries | 250M artifacts exposed, 2,100+ registries with upload access | 2023-2024 |
| §5-2 + §1-1 | OIDC Misconfigurations (OH-MY-DC) | Privilege escalation via OIDC + PPE (DEF CON 32) | Aug 2024 |

---

## Detection & Defense Tools

### Offensive / Red Team Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Raven** (Cycode) | CI/CD security analysis | Pipeline misconfiguration detection |
| **zizmor** | GitHub Actions workflows | Workflow vulnerability scanning |
| **gitrob** | GitHub/GitLab | Secret and sensitive file discovery |
| **TruffleHog** | Git repositories | Historical secret scanning across commits |

### Defensive / Blue Team Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Snyk** | Dependencies, containers, IaC | Vulnerability detection in software supply chain |
| **Trivy** | Container images, IaC, dependencies | Open-source vulnerability scanner |
| **Checkov** | Infrastructure as Code | IaC static analysis for misconfigurations |
| **TruffleHog** (defensive) | Pre-commit hooks, CI integration | Block secrets before commit |
| **GitGuardian** | Source code, CI logs | Real-time secret detection and alerting |
| **SonarQube** | Code quality and security | SAST scanning in CI pipelines |
| **JFrog Xray** | Artifact repositories | Artifact security and compliance scanning |
| **Aqua Security** | Container security | Runtime and build-time container protection |
| **StepSecurity Harden-Runner** | GitHub Actions | Runtime monitoring, network egress control |
| **OX Security** | CI/CD pipelines | Pipeline security posture management |
| **Boost Security** | CI/CD pipelines | Pipeline vulnerability detection |
| **OWASP Dependency-Check** | Dependencies | OWASP-maintained dependency vulnerability scanner |

### Research & Fuzzing Tools

| Tool | Purpose | Methodology |
|------|---------|-------------|
| **Semgrep** | Pattern-based code scanning | Custom rules for CI/CD misconfigurations |
| **CodeQL** | Semantic code analysis | Query-based vulnerability detection |
| **Nuclei** | CI/CD endpoint scanning | Template-based vulnerability detection |

---

## Summary: Core Principles

### The Fundamental Problem

CI/CD pipelines sit at the intersection of **trust, automation, and access**. They are inherently privileged — holding secrets, deploying to production, and executing untrusted code from pull requests. This creates a structural vulnerability: *any mechanism that allows external input to influence pipeline behavior becomes an attack vector*.

The core issue is the **collapsing of trust boundaries**. Modern development workflows prioritize velocity over security, leading to:

1. **Configuration as Code** → Attackers can modify execution logic via pull requests
2. **Automated Trust** → Pipelines trust repository content, dependencies, and third-party actions by default
3. **Credential Proliferation** → Secrets must be accessible to automation, creating exposure risk
4. **Shared Infrastructure** → Runners, caches, and registries used across repositories create lateral movement opportunities

### Why Incremental Fixes Fail

Organizations applying point solutions face recurring compromises because:

- **Secret scanning** doesn't prevent runtime exfiltration or memory scraping
- **Branch protection** is bypassed via GitHub Actions tokens or PPE
- **Dependency scanning** misses supply chain attacks (dependency confusion, malicious updates to clean packages)
- **SBOM generation** occurs too late or from compromised build environments
- **Container scanning** focuses on CVEs, not novel malware or backdoors
- **Access controls** are circumvented via privilege escalation (OIDC, token abuse)

Each defensive control operates in isolation, while attackers chain mutations across **multiple layers** (§1 configuration + §3 secrets + §7 runner = full compromise).

### The Structural Solution

Effective CI/CD security requires **defense in depth** with **least privilege** and **zero trust** principles:

1. **Immutable Infrastructure**: Ephemeral runners destroyed after each job (preventing §7-1 persistence)
2. **Pipeline Isolation**: Separate pipelines for untrusted code (forks, PRs) from production deployments
3. **Just-In-Time Secrets**: OIDC federation with short-lived tokens, never long-lived credentials (mitigates §3-1, §3-3)
4. **Artifact Signing & Verification**: Cryptographic verification at every stage (defeats §6-1, §6-2)
5. **Dependency Pinning**: Lock files with hash verification, vendored dependencies (blocks §4-1, §4-2)
6. **Configuration Review**: All workflow changes require human approval from CODEOWNERS (prevents §1-1, §1-3)
7. **Network Segmentation**: Egress filtering on runners, monitor outbound connections (detects §3-1, §7-3)
8. **Expression Sandboxing**: Never interpolate untrusted data into shell or expression contexts (eliminates §8-2)
9. **OWASP CICD-SEC Alignment**: Systematically address all 10 OWASP CI/CD security risks
10. **Supply Chain Transparency**: SBOM generation from trusted build systems, provenance attestation (SLSA framework)

**The only sustainable defense is architectural**: treating CI/CD as a security-critical system with the same rigor applied to production infrastructure. Incremental tooling is necessary but insufficient — systemic change requires rethinking how code flows from commit to deployment.

The 2024-2025 attack wave (Shai-Hulud, tj-actions, Ultralytics) demonstrates that **CI/CD is now the primary target** for supply chain compromise. Organizations that fail to adopt zero-trust CI/CD architectures will face repeated, escalating attacks.

---

## References

### Academic & Conference Research
- OH-MY-DC: OIDC Misconfigurations in CI/CD (DEF CON 32, August 2024)
- ARGUS: Static Taint Analysis of GitHub Workflows (USENIX Security 2023)
- Poisoned Pipeline Execution research (MITRE ATT&CK T1677)
- PromptPwnd: GitHub Actions AI Agent Vulnerabilities (Aikido Security, 2025)

### Industry Reports & Whitepapers
- OWASP Top 10 CI/CD Security Risks (2024)
- The 2025 State of Pipeline Security (Boost Security)
- Supply Chain Attack Statistics 2025 (DeepStrike)
- Misconfigured Registries: 250 Million Artifacts Exposed (Aqua Security, 2023)

### Vulnerability Disclosures & Advisories
- GitHub Security Lab Advisories (GHSL-2024 series)
- CISA Known Exploited Vulnerabilities Catalog
- CVE Details (CVEs 2024-2025)
- National Vulnerability Database (NVD)

### Practitioner Blogs & Writeups
- Bypassing Required Reviews Using GitHub Actions (Cider Security)
- Self-Hosted GitHub Runners as Backdoors (Praetorian, Sysdig)
- Dependency Confusion Attacks and Prevention (GitGuardian)
- GitHub Actions Exploitation Series (Synacktiv)

### Tool Documentation & Frameworks
- SLSA (Supply-chain Levels for Software Artifacts) Framework
- Sigstore (Artifact Signing)
- in-toto (Supply Chain Integrity)
- PEP 708: Mitigating Dependency Confusion (Python)

### Major Incident Reports
- Shai-Hulud 2.0 Supply Chain Attack (Microsoft Security Blog, Check Point, Wiz)
- tj-actions/changed-files Compromise Analysis (Unit 42, Semgrep, CISA)
- Ultralytics PyPI Compromise Postmortem
- GhostAction Supply Chain Attack (GitGuardian)

---

*This document was created for defensive security research, vulnerability understanding, and secure CI/CD architecture design purposes. The techniques described are documented to enable defenders to understand the threat landscape and implement appropriate controls.*

**Last Updated**: February 2026
**Coverage Period**: Primarily 2024-2025 incidents and research
