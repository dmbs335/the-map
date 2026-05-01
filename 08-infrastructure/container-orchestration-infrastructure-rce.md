# Container & Orchestration Infrastructure RCE — Mutation/Variation Taxonomy

*Comprehensive classification of Remote Code Execution attack surfaces across container runtimes, orchestration platforms, container build systems, image supply chains, and cloud-managed Kubernetes environments. This taxonomy covers the full lifecycle — from image build through registry distribution, runtime execution, orchestration, and cloud-provider integration — organizing every mutation by the structural component being exploited.*

---

## Classification Structure

Container and orchestration infrastructure creates a layered security boundary between workloads and the host system. At the lowest level, Linux kernel primitives (namespaces, cgroups, seccomp, LSMs) isolate processes. Container runtimes (runc, containerd, CRI-O) manage these primitives. Orchestration platforms (Kubernetes) layer RBAC, admission control, and network policy atop the runtime. Cloud providers (EKS, AKS, GKE) add managed control planes and identity services. Each layer introduces its own RCE surfaces — a vulnerability at any layer can cascade upward or downward, and attack chains routinely span multiple layers.

This taxonomy organizes the attack surface along three axes:

**Axis 1 — Structural Target (Primary, §1–§9):** The infrastructure component being exploited to achieve code execution. This axis structures the main body of the document: container runtime internals, kernel interfaces, privileged configurations, orchestration control plane, admission/extension points, build systems, image supply chain, network/service mesh fabric, and cloud-provider integration.

**Axis 2 — Exploitation Primitive (Cross-cutting):** The fundamental technique by which the container boundary is breached or code execution is achieved:

| Primitive | Description | Primary Sections |
|---|---|---|
| **Race Condition / TOCTOU** | Exploiting timing windows during container initialization to redirect mounts, symlinks, or file descriptors | §1 |
| **File Descriptor / Handle Leak** | Leaked FDs to host resources (runc binary, procfs, cgroupfs) provide escape primitives | §1 |
| **Privilege Abuse** | Exploiting granted capabilities, privileged mode, or host mounts to break isolation by design | §2 |
| **Configuration Injection** | Injecting directives into NGINX configs, Helm templates, operator CRDs, or admission webhooks to achieve code execution | §4, §5 |
| **API Abuse** | Exploiting unauthenticated or over-permissioned API endpoints (Docker API, kubelet, etcd, admission webhooks) | §3, §4 |
| **Kernel Exploitation** | Using kernel vulnerabilities (eBPF verifier bugs, cgroup escapes, namespace bypasses) to break out of shared-kernel containers | §1 |
| **Supply Chain Poisoning** | Inserting malicious code into base images, build pipelines, Helm charts, or OCI hooks executed during container lifecycle | §6, §7 |
| **Credential Theft / Identity Abuse** | Stealing service account tokens, IMDS credentials, or mTLS certificates to escalate within the cluster or cloud account | §3, §8, §9 |
| **Lateral Movement** | Pivoting from compromised container through default-open network policies, shared volumes, or node-level access | §3, §8 |

**Axis 3 — Attack Scenario (Mapping, §10):** The real-world deployment context — single-container escape, cross-container pivot, node takeover, cluster-wide compromise, and cross-tenant cloud account breach.

---

## §1. Container Runtime Escape

The container runtime (runc, containerd, CRI-O, crun) is responsible for creating the isolation boundary between the container process and the host. Vulnerabilities in runtime initialization, filesystem setup, or process management provide direct host-level code execution from within a non-privileged container — the most critical class of container RCE.

### §1-1. procfs/sysfs Mount Race Conditions

During container startup, the runtime creates bind-mounts to "mask" sensitive host paths under `/proc` and `/dev`. Race conditions in this initialization allow an attacker to substitute symlinks before the runtime completes its setup, redirecting bind-mounts to arbitrary host files.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **/dev/null symlink redirect** | During container creation, runc bind-mounts `/dev/null` over sensitive procfs paths. By replacing `/dev/null` with a symlink to a target like `/proc/sys/kernel/core_pattern` before the bind-mount occurs, the attacker gains read-write access to the host procfs entry. Writing a pipe command to `core_pattern` (e.g., `|/path/to/payload`) achieves host-level code execution on the next core dump | runc ≤ 1.2.4 (CVE-2025-31133); ability to start containers with custom mount configurations; most likely delivered via malicious container images |
| **/dev/console bind-mount race** | The `/dev/console` bind-mount path can be exploited through similar race/symlink techniques during container initialization, granting write access to critical procfs entries | runc ≤ 1.2.4 (CVE-2025-52565); requires container start privilege with custom mounts |
| **LSM label write redirect** | By making `/proc/self/attr/<label>` reference a real procfs file, an attacker redirects Linux Security Module label writes to arbitrary procfs targets. This bypasses LSM checks entirely — writes intended for security label files are redirected to targets like `/proc/sysrq-trigger` (host crash) or `/proc/sys/kernel/core_pattern` (container breakout) | runc ≤ 1.2.4 (CVE-2025-52881); requires container start privilege; bypasses SELinux/AppArmor relabel protections |
| **Masked path timing window** | The general class: any runtime that uses bind-mounts to mask host paths during container init creates a TOCTOU window between path creation and mount completion. Attack patterns include replacing target paths with symlinks, manipulating mount propagation, or exploiting PID namespace ordering | Any runtime using bind-mount masking without atomic operations |

### §1-2. File Descriptor Leaks

Container runtimes fork child processes to set up the container environment. If file descriptors referencing host resources are not properly closed before the container process gains control, they become escape primitives.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **/proc/self/exe FD overwrite** | runc leaks a file descriptor to its own binary (`/proc/self/exe`) during container init. An attacker inside the container uses this leaked FD to overwrite the host's runc binary with a malicious payload. The next time any container operation invokes runc (e.g., `docker exec`, `kubectl exec`), the attacker's code executes with host-level root privileges | runc ≤ 1.1.11 (CVE-2024-21626, "Leaky Vessels"); FD not properly closed during container init; CVSS 8.6 |
| **cgroupfs FD escape** | runc fails to close the file descriptor to `/sys/fs/cgroup` in time when forking child processes. Child processes access the host filesystem through `/proc/self/fd/<fdnum>`, using the leaked cgroupfs descriptor as a pivot point to traverse to host paths | runc ≤ 1.1.11 (CVE-2024-21626 variant); default Kubernetes seccomp profile does not block this |
| **Working directory FD leak** | If the container's working directory is set to a path like `/proc/self/fd/7` and FD 7 references a host directory, the container process starts with its CWD on the host filesystem | runc ≤ 1.1.11 (CVE-2024-21626); `WORKDIR /proc/self/fd/N` in Dockerfile triggers the escape |

### §1-3. OCI Hook Exploitation

The OCI runtime specification defines lifecycle hooks (prestart, createRuntime, createContainer, startContainer, poststop) that execute during container lifecycle events. These hooks run in the host context and can inherit untrusted data from the container.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Environment variable inheritance in createContainer hook** | The `createContainer` OCI hook inherits environment variables from the container image without sanitization. Setting `LD_PRELOAD=/malicious/lib.so` in a Dockerfile causes the hook process to load an attacker-controlled shared library in the host context, achieving host-level code execution — exploitable with a minimal Dockerfile | NVIDIA Container Toolkit ≤ 1.17.7 (CVE-2025-23266, "NVIDIAScape", CVSS 9.0); affects GPU-enabled container environments |
| **TOCTOU in runtime mount operations** | A TOCTOU race in how the NVIDIA Container Toolkit handles container filesystem mounts allows an attacker to escalate from container access to full host takeover. The attack exploits the time gap between when a path is validated and when it is actually used | NVIDIA Container Toolkit ≤ 1.16.1 (CVE-2024-0132, CVSS 9.0); demonstrated on Replicate, Hugging Face, and other AI platforms |
| **Custom runtime shim exploitation** | Third-party runtime shims (GPU runtimes, WASM runtimes, gVisor, Kata) implement OCI hooks and lifecycle handlers. Vulnerabilities in these shims inherit the host-context privilege of the hook execution model | Any runtime with custom OCI hook implementations |

### §1-4. Kernel-Level Container Escape

Containers share the host kernel — any kernel vulnerability is potentially a container escape. Certain kernel subsystems are disproportionately exploitable from within containers.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **eBPF verifier bypass** | The eBPF verifier validates BPF programs before loading. Bugs in the verifier (type confusion, bounds tracking errors) allow crafting BPF programs that perform out-of-bounds kernel memory access. From within a privileged container (default Kubernetes configuration), this achieves arbitrary kernel read/write and container escape | CAP_SYS_ADMIN or CAP_BPF; out-of-the-box Kubernetes still applies `Unconfined` seccomp by default — the `SeccompDefault` feature gate graduated to stable in v1.27 but remains opt-in via the kubelet `--seccomp-default=true` flag (or `seccompDefault: true` in the kubelet config). When enabled, the container-runtime `RuntimeDefault` profile blocks `bpf()` for non-CAP_SYS_ADMIN containers, closing this path (CVE-2021-3490, CVE-2021-31440, CVE-2022-23222; multiple 2024 variants) |
| **cgroup release_agent execution** | cgroups v1 `release_agent` mechanism runs a host-level binary when a cgroup's last process exits. By writing a path to `release_agent` and triggering process termination within the cgroup, an attacker executes arbitrary commands as root on the host | cgroups v1 with notify_on_release; unconfined container or missing AppArmor/seccomp (CVE-2022-0492); still exploitable on systems supporting cgroups v1 for backwards compatibility |
| **User namespace exploitation** | Unprivileged user namespaces allow creating nested namespace configurations that expose additional kernel attack surface. Combined with other kernel bugs, user namespaces amplify the exploitability of local privilege escalation vulnerabilities from within containers | `CONFIG_USER_NS=y` (default on most distributions); unprivileged user namespace creation enabled |
| **Cross-node eBPF attacks** | eBPF programs loaded on one node can monitor and manipulate network traffic, processes, and filesystem operations across all containers on that node. Research demonstrates that all existing cloud security products can be bypassed by malicious eBPF programs, and default Kubernetes clusters of three major cloud vendors are vulnerable to cross-node attacks | CAP_BPF or CAP_SYS_ADMIN; network-level access between nodes |

### §1-5. Build-Time Container Escape

Container build systems (BuildKit, Buildah, Kaniko) execute Dockerfiles/Containerfiles, creating an attack surface where build instructions escape the build sandbox.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **BuildKit mount cache race** | A race condition during BuildKit's mount cache handling allows an attacker to manipulate the container's temporary directories during image building, achieving container breakout and host filesystem access | BuildKit ≤ 0.12.4 (CVE-2024-23651, "Leaky Vessels"; CVSS 8.7) |
| **BuildKit arbitrary file deletion** | A flaw in BuildKit allows attackers to manipulate temporary directories to delete arbitrary files on the host system during image building | BuildKit ≤ 0.12.4 (CVE-2024-23652; CVSS 9.1) |
| **BuildKit GRPC privilege escalation** | Vulnerabilities in BuildKit's GRPC interface enable attackers to break out of containers during the image-building process by abusing build privileges | BuildKit ≤ 0.12.4 (CVE-2024-23653; CVSS 9.8) |
| **Buildah mount source symlink** | During build-time volume processing, Buildah resolves mount sources without following symlinks. A specially-crafted image containing a symlink to the host root (`/`) as a mount source causes Buildah to mount the entire host filesystem into the build container | Buildah (CVE-2024-1753; CVSS 8.6); exploitable via malicious Containerfiles |
| **Kaniko unprivileged build context** | Kaniko runs builds in userspace without a Docker daemon. While this reduces the attack surface, Kaniko builds execute in the same container that holds the build context — malicious Dockerfiles with `RUN` instructions execute arbitrary commands in the Kaniko container, which may have access to registry credentials, CI/CD secrets, or cloud identity metadata | Kaniko in CI/CD with mounted secrets or cloud identity |

---

## §2. Privileged Container & Capability Abuse

Containers running with elevated privileges (--privileged flag, dangerous Linux capabilities, host namespace sharing, sensitive volume mounts) provide direct escape paths without requiring any vulnerability — the escape is by design. This category represents the most common real-world container breakout vector.

### §2-1. Host Mount Exploitation

Sensitive host paths mounted into containers — whether intentionally or through misconfiguration — provide direct access to host resources.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Docker socket mount** | Mounting `/var/run/docker.sock` grants full Docker API access. The attacker creates a new privileged container with the host filesystem mounted: `docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host sh` | Docker socket exposed inside container |
| **hostPath root mount** | `hostPath: /` (or sensitive paths like `/etc`, `/var/run`, `/var/lib/kubelet`) mounted into a pod provides direct read/write access to the host filesystem. Write a cron job to `/etc/crontab`, modify `/etc/shadow`, or plant an SSH key in `/root/.ssh/authorized_keys` | Kubernetes pod spec with `hostPath` pointing to sensitive paths; PodSecurityPolicy not enforcing hostPath restrictions |
| **PersistentVolume hostPath bypass** | When PodSecurityPolicy restricts `hostPath` in pod specs, an attacker with PV/PVC creation permissions creates a hostPath-type PersistentVolume, then mounts it via PersistentVolumeClaim — effectively bypassing the PSP restriction because PV objects are not validated against pod-level security policies | PV creation permissions; PSP not validating PV types (TOB-K8S-038) |
| **kubelet pods directory mount** | Mounting `/var/lib/kubelet/pods` exposes service account tokens from every pod on the node. The attacker traverses the directory to extract tokens from privileged system accounts (e.g., kube-proxy, monitoring agents, ingress controllers) | hostPath mount to kubelet pods directory |
| **containerd/CRI socket mount** | Mounting the containerd socket (`/run/containerd/containerd.sock`) or CRI socket provides container runtime API access. The attacker uses `ctr` or `crictl` to create privileged containers, exec into existing containers, or extract images with embedded secrets | Container runtime socket exposed inside pod |

---

## §3. Orchestration Control Plane RCE

The Kubernetes control plane (kube-apiserver, etcd, kube-controller-manager, kube-scheduler, kubelet) manages cluster state and enforces security policy. Compromising any control plane component achieves cluster-wide impact — from node-level code execution to exfiltration of every secret in the cluster.

### §3-1. Kubernetes API Server Exploitation

The kube-apiserver is the gateway to all cluster operations. Unauthenticated access, RBAC misconfiguration, or API-level vulnerabilities provide direct cluster compromise.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Anonymous authentication to API server** | When `--anonymous-auth=true` (the default) and RBAC is misconfigured to grant anonymous users cluster-admin or broad permissions, any network-accessible client can list secrets, create pods, and execute arbitrary commands cluster-wide | `anonymous-auth=true` + overly permissive RBAC for `system:anonymous` |
| **nodes/proxy GET → RCE** | A service account with `nodes/proxy GET` permission — routinely granted to monitoring tools (Prometheus, Datadog, Grafana) — can establish WebSocket exec sessions through the kubelet API and execute arbitrary commands in any container on any reachable node. This bypasses the `CREATE` verb check that should be required for exec operations. Default kube-apiserver audit policies typically log only the proxy verb at the apiserver and do not capture the downstream kubelet exec/attach traffic; a stricter audit profile (or kubelet-side audit) can be configured to surface these, but it is not on by default | `nodes/proxy GET` permission; no CVE assigned — Kubernetes considers this "working as intended" |
| **RBAC escalation via bind/escalate** | Users with `bind` or `escalate` permissions on ClusterRoles/Roles can create role bindings that grant themselves cluster-admin privileges. The `escalate` verb allows modifying a role to add any permissions, while `bind` allows binding any role to any subject | `bind` or `escalate` verb permissions on Role/ClusterRole resources |
| **Impersonation abuse** | Users with impersonation rights (`--as=system:admin`, `--as-group=system:masters`) can act as any user or group, including cluster-admin. Impersonation permissions are sometimes granted broadly to CI/CD service accounts | `impersonate` verb on users/groups/serviceaccounts |
| **Windows log query command injection** | The `nodes/*/logs/query` API endpoint on Windows nodes does not validate the `Pattern` parameter, allowing PowerShell command injection via GET requests: `?query=nssm&pattern='$(Start-Process cmd)'` — achieving SYSTEM-level RCE on all Windows endpoints | Kubernetes with Log Query feature enabled on Windows nodes (CVE-2024-9042; CVSS 5.9) |

### §3-2. kubelet API Exploitation

The kubelet runs on every node, managing pod lifecycle. Its API (port 10250) provides pod enumeration, exec, and log access — often without adequate authentication.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unauthenticated kubelet API** | The kubelet API on port 10250, when configured with `--authentication-token-webhook=false` or `--anonymous-auth=true`, allows any network-accessible client to enumerate all pods on the node, execute commands inside any container, read container logs, and port-forward to pod ports — all without credentials | kubelet with anonymous auth enabled; approximately 287,000 kubelet APIs exposed to the internet as of 2025 |
| **Read-only kubelet API information leak** | Port 10255 (read-only kubelet API) exposes pod specs, environment variables, container statuses, and node metrics without authentication. Environment variables often contain database credentials, API keys, and cloud provider credentials | `--read-only-port=10255` (default on many older configurations) |
| **kubelet exec bypass audit** | Commands executed through direct kubelet API access (`/exec/<namespace>/<pod>/<container>`) bypass the Kubernetes API server entirely, meaning standard Kubernetes audit policies do not log the operations. Attackers establish persistent access and exfiltrate data without audit trail | Direct network access to kubelet port; no audit logging for kubelet-direct operations |

### §3-3. etcd Direct Access

etcd stores all cluster state, including Secrets (base64-encoded, not encrypted by default), RBAC policies, and pod specifications. Direct etcd access equals unrestricted cluster control.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unauthenticated etcd access** | etcd exposed without TLS client certificate authentication allows any client to read/write all cluster data. A single `etcdctl get --prefix /` command dumps every secret in the cluster | etcd without `--client-cert-auth`; exposed to network (port 2379) |
| **etcd data at rest unencrypted** | Kubernetes Secrets are stored as base64-encoded values in etcd by default — not encrypted. Anyone with etcd filesystem access (backup tapes, snapshot files, compromised node) can decode all secrets. Production adoption of encryption at rest varies widely | etcd without `EncryptionConfiguration`; default Kubernetes installation |
| **etcd snapshot exfiltration** | etcd snapshot files (`etcdctl snapshot save`) contain the entire cluster state. If snapshot files are stored in accessible locations (shared storage, backup services, CI/CD artifacts), they can be retrieved and restored offline to extract all secrets | etcd snapshots in accessible storage; insufficient backup encryption |

### §3-4. Service Account Token Exploitation

Every pod receives an automatically mounted service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Overpermissioned service accounts turn any container compromise into a cluster-level attack.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Default service account overpermission** | The `default` service account in a namespace is bound to cluster-admin or broad ClusterRoles. Every pod in that namespace inherits cluster-admin access through its auto-mounted token | RBAC binding giving cluster-admin to default service accounts |
| **Token volume mount traversal** | From a compromised pod with access to `/var/lib/kubelet/pods` (via hostPath mount), an attacker traverses to extract service account tokens from every pod on the node, including system-critical pods (kube-proxy, monitoring agents, ingress controllers) | hostPath mount to kubelet pods directory (§2-1) |
| **Long-lived non-expiring tokens** | Legacy Kubernetes (pre-1.24) creates non-expiring service account tokens stored as Secrets. These tokens remain valid indefinitely even after the associated pod is deleted, and can be extracted from etcd, logs, or environment variables | Kubernetes < 1.24 or clusters with legacy token creation; tokens persisted in Secrets |
| **RBAC Buster persistence** | An attacker creates a ClusterRoleBinding from a compromised pod, binding a new service account to cluster-admin. This binding persists even after the initial misconfiguration is fixed, providing permanent backdoor access | Service account with ClusterRoleBinding creation permissions |

---

## §4. Admission & Extension Point Exploitation

Kubernetes admission controllers and extension mechanisms (webhooks, operators, CRDs) process and transform workload specifications before deployment. Vulnerabilities in these components provide unauthenticated or low-privilege paths to code execution.

### §4-1. Admission Webhook RCE

Admission webhooks (validating and mutating) intercept API requests before they are persisted. Webhook implementations that process untrusted input from workload specifications are vulnerable to injection attacks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Ingress annotation injection → NGINX config injection → RCE** | The Ingress NGINX admission controller constructs NGINX configuration from Ingress annotations (`auth-url`, `auth-tls-match-cn`, `mirror-target`) without adequate sanitization. Attackers inject arbitrary NGINX directives (including `ssl_engine`, `load_module`, or lua_code_cache) that cause the NGINX validator to execute code — achieving RCE in the ingress controller pod. Because the ingress controller has a highly-permissioned service account with cluster-wide Secret access, this escalates to full cluster takeover | Ingress NGINX Controller < 1.11.5/1.12.1; annotation injection CVEs CVE-2025-1097, CVE-2025-1098, CVE-2025-24514 are CVSS 8.8, while admission-controller RCE CVE-2025-1974 "IngressNightmare" is CVSS 9.8; broad cloud exposure reported by third-party research |
| **Admission webhook bypass via namespace** | Some admission webhooks exclude system namespaces (kube-system, kube-public) from validation. Attackers who can create resources in excluded namespaces bypass all admission policies | Webhook with `namespaceSelector` excluding system namespaces |
| **Webhook denial of service → policy bypass** | If a validating webhook is configured with `failurePolicy: Ignore`, overwhelming or crashing the webhook allows all requests to pass without validation — effectively disabling security policies | `failurePolicy: Ignore` on security-critical webhooks |

### §4-2. Operator & CRD Exploitation

Kubernetes Operators watch Custom Resource Definitions (CRDs) and create/modify cluster resources. Operators with broad RBAC permissions that process untrusted CRD input can be weaponized.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CRD input injection → resource creation** | An operator's controller takes user-supplied fields from a CRD object and uses them to construct YAML manifests for deployment without validation. An attacker injects additional Kubernetes resource definitions (e.g., privileged pods, ClusterRoleBindings) through CRD fields | Operator processing unsanitized CRD input; operator service account with broad permissions |
| **Operator privilege escalation via CRD** | An attacker with namespace-level permission to create CRD objects triggers an operator to deploy resources with higher privileges than the attacker's own role — e.g., creating a pod with `hostPID: true` or a ClusterRoleBinding to cluster-admin | CVE-2025-2843 (Observability Operator); operator's service account has cluster-admin |
| **Operator self-privilege escalation** | An operator pod deploys pods with higher privileges than itself, because operator RBAC allows creating pods but doesn't restrict the security context of those pods. An operator granted `create pods` can create `--privileged` pods | Operator RBAC without PodSecurity admission enforcement |

### §4-3. gitRepo Volume Exploitation

The deprecated `gitRepo` volume type clones Git repositories onto the node filesystem (not inside the pod) during pod creation. This mechanism executes Git hooks with node-level privileges.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Git hook execution on node** | A malicious Git repository containing executable hooks (`.git/hooks/post-checkout`, `.git/hooks/pre-commit`) or submodule configurations triggers hook execution during `git clone` on the node. Since the clone runs as kubelet (root), this achieves node-level RCE | gitRepo volume support enabled; pod creation permissions (CVE-2024-10220; CVSS 8.1) |
| **Submodule URL hijacking** | `.gitmodules` references external repositories. When the gitRepo volume clones the main repository, submodule initialization fetches from attacker-controlled URLs, potentially triggering additional hook execution or SSRF | gitRepo volume with recursive submodule initialization |

---

## §5. Ingress, Load Balancer & Proxy Exploitation

Components that handle external traffic entry into the cluster — ingress controllers, service meshes, and API gateways — process untrusted input and often run with elevated privileges.

### §5-1. Ingress Controller Configuration Injection

Ingress controllers translate Kubernetes Ingress resources into reverse-proxy configurations. Injection into these configurations achieves code execution in the proxy process, which typically has access to TLS certificates and cluster-wide routing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **NGINX config directive injection** | Through Ingress annotations or custom snippets, attackers inject NGINX configuration directives. The `ssl_engine` directive loads a shared library at NGINX startup — a crafted `.so` file achieves arbitrary code execution. Alternatively, Lua code blocks (`content_by_lua_block`) execute arbitrary code in the NGINX worker process | Ingress NGINX with custom snippet support enabled; annotation injection via §4-1 |
| **NGINX shared library loading** | The `load_module` directive or `ssl_engine` directive in injected NGINX configuration loads an attacker-controlled shared object from a path within the ingress controller's filesystem (written via ConfigMap mount, PVC, or tmpdir manipulation) | Ingress NGINX configuration injection + writable filesystem path |
| **HAProxy / Envoy configuration injection** | Alternative ingress controllers (HAProxy, Envoy-based Contour/Ambassador) process similar annotation-driven configurations. Template injection in these systems can alter routing rules, enable debug endpoints, or load external modules | Ingress controller processing unsanitized annotations |

### §5-2. Service Mesh Identity Theft

Service meshes (Istio, Linkerd) inject sidecar proxies that handle mTLS authentication between services. Compromising the sidecar or its credentials enables identity impersonation across the mesh.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sidecar mTLS certificate theft ("Sidecar Siphon")** | In sidecar-based service meshes, the application container and the Envoy sidecar share the same network namespace. A breached application container reads the sidecar's mTLS certificates from the shared volume or filesystem, then uses them to impersonate the service — making authenticated requests to any other service in the mesh | Istio with sidecar injection; shared network namespace between app and sidecar; service account token accessible |
| **Service account token → CA certificate signing** | The sidecar's service account token enables performing a Certificate Signing Request (CSR) to the mesh CA (istiod). An attacker who obtains the SA token can request valid mTLS certificates for any service identity | Istio with in-cluster CA; service account token mounted in pod |

---

## §6. Container Image & Registry Supply Chain

The container image lifecycle — from base image selection through registry distribution — presents supply chain attack surfaces where malicious code is embedded in images that appear legitimate, executing during build, pull, or runtime.

### §6-1. Registry-Level Attacks

Container registries (Docker Hub, Harbor, Quay, ACR, ECR, GCR) are trust anchors for image distribution. Compromising registry integrity provides wide-scale malicious code distribution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Image typosquatting** | Publishing malicious images with names resembling popular official images (e.g., `openjdk` vs `OpenJDK`, `golang` vs `Golang`, `alpline` vs `alpine`). Public registry research repeatedly finds malware-heavy typosquatting campaigns, often with cryptocurrency theft as the objective | Public registry (Docker Hub); no image signature verification; developer typing errors |
| **Base image backdoor persistence** | Compromised or intentionally backdoored base images embed persistent malware in layers. The XZ Utils supply chain backdoor (CVE-2024-3094, CVSS 10.0) was found propagating through Docker Hub images as late as September 2025, surviving in dozens of derivative images long after the upstream fix | Public base images without signature verification; transitive dependency propagation |

### §6-2. Image Content Attacks

Malicious content within legitimate-looking container images executes during build, pull, or container startup.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dockerfile RUN instruction RCE** | `RUN` instructions in Dockerfiles execute arbitrary commands during build. Supply chain attacks inject malicious Dockerfiles that exfiltrate build secrets (Docker config, registry credentials, CI/CD tokens) or embed persistent backdoors in the resulting image | Automated CI/CD building untrusted Dockerfiles |
| **ENTRYPOINT/CMD backdoor** | A modified entrypoint script downloads and executes malicious payloads at container startup while still running the expected application. The backdoor is invisible in layer inspection if disguised within legitimate initialization scripts | Pull-and-run without image verification; backdoor in initialization scripts |
| **Multi-stage build secret leak** | Secrets available during build stages (ARG-passed credentials, mounted secret files) persist in intermediate layers even when not copied to the final stage, if the intermediate layers are pushed to a registry or cached | Multi-stage builds with leaked secrets in non-final stages; layer caching in registries |
| **Malicious container init process** | Self-propagating malware runs as the container's init process, scans the network for exposed Docker APIs and Kubernetes services, deploys cryptocurrency miners, and propagates to additional hosts. The "nginx" malware variant discovered in 2025 operates this way | Exposed Docker API; containers with network access to scan external hosts |

---

## §7. Docker Engine & Desktop API Exploitation

Docker Engine exposes an API for container management. When this API is accessible without authentication — whether locally, over the network, or due to architectural flaws — it provides full container (and by extension, host) control.

### §7-1. Remote Docker API Exposure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **TCP 2375 unauthenticated API** | Docker Engine listening on TCP port 2375 without TLS allows any network client to create containers, mount the host filesystem, and execute commands as root. Automated botnets scan the internet for exposed Docker APIs: `docker -H tcp://target:2375 run -v /:/host --privileged alpine sh` | Docker configured with `-H tcp://0.0.0.0:2375` without TLS; internet-exposed host |
| **Docker Swarm botnet recruitment** | After discovering exposed Docker APIs, attackers join the target into an attacker-controlled Docker Swarm, deploying cryptocurrency miners and lateral movement tools across the swarm. The 2024 campaign used masscan and ZGrab for internet-wide scanning of Docker API ports | Exposed Docker API; Docker Swarm mode available |
| **Self-propagating container malware** | Malicious containers running on exposed Docker APIs scan the internet for additional exposed APIs, creating worm-like propagation. The Dero cryptocurrency miner campaign (2025) used this technique to build a distributed mining network | Exposed Docker API; outbound network access from containers |

---

## §8. Cluster Network & Lateral Movement

Kubernetes default networking allows unrestricted pod-to-pod communication. After initial container compromise, the network layer enables lateral movement to high-value targets: databases, internal APIs, control plane components, and cloud metadata services.

### §8-1. Default Network Policy Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unrestricted pod-to-pod communication** | Kubernetes does not enforce network policies by default — all pods can communicate with all other pods across all namespaces. A compromised pod has network access to every database, internal API, and control plane component in the cluster | No NetworkPolicy objects deployed; default CNI configuration |
| **DNS-based service discovery for targeting** | Kubernetes CoreDNS resolves service names for every namespace. A compromised pod queries `*.svc.cluster.local` to enumerate all services, then targets high-value endpoints: databases, key-value stores, admin panels, and monitoring dashboards | Default CoreDNS configuration; no DNS-level restrictions |
| **IP spoofing between pods** | Without CNI-level protections, pods can spoof their source IP addresses to impersonate other pods, bypassing NetworkPolicy rules that rely on source IP for access control | CNI without IP spoofing prevention (Flannel, basic bridge CNI); no eBPF-based identity verification |

### §8-2. Cloud Metadata Service (IMDS) Access

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IMDSv1 credential theft** | Pods with host network access or without IMDS restrictions can reach the cloud metadata endpoint (`http://169.254.169.254/latest/meta-data/`) to retrieve the node's IAM role credentials. These credentials provide access to cloud resources (S3, RDS, DynamoDB) with the node's permissions — often broader than intended for any single workload | EKS/AKS/GKE with IMDSv1 enabled (default on older configurations); no `--metadata-options HttpEndpoint=disabled` |
| **IMDSv2 bypass via hop limit** | IMDSv2 requires a token obtained via PUT request with a TTL hop limit of 1 (to prevent SSRF-based access). However, pods running with `hostNetwork: true` have a hop count of 0 to the IMDS endpoint, bypassing the hop limit restriction | `hostNetwork: true` + IMDSv2 with default hop limit |
| **Managed identity token theft** | In AKS, the Azure Instance Metadata Service exposes managed identity tokens. An attacker in any pod can request tokens for the node's managed identity, which may have permissions to Azure Key Vault, Azure Storage, or other cloud services | AKS with node-level managed identity; no pod identity isolation |
| **GKE metadata concealment bypass** | Older GKE configurations expose node service account credentials via the metadata server. While Workload Identity is the recommended mitigation, clusters not using Workload Identity expose GCP IAM credentials to every pod on the node | GKE without Workload Identity; legacy metadata API enabled |

---

## §9. Cloud-Managed Kubernetes & Multi-Tenant Isolation

Cloud-managed Kubernetes services (EKS, AKS, GKE) introduce provider-specific attack surfaces through managed control planes, node provisioning, identity integration, and multi-tenant isolation boundaries.

### §9-1. Managed Control Plane Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **AKS TLS Bootstrap credential theft** | A vulnerability in Azure Kubernetes Service allowed attackers to leverage Azure WireServer to retrieve encryption keys used for decrypting provisioning scripts, which contain sensitive credentials for bootstrapping cluster nodes | AKS with vulnerable WireServer configuration (2024 disclosure) |
| **EKS Pod Identity Agent exploitation** | The EKS Pod Identity Agent runs as a DaemonSet on every node. If an attacker compromises the agent's pod or its communication channel, they can intercept or forge identity tokens for any pod on the node | EKS with Pod Identity; agent compromise via container escape |
| **GKE Autopilot policy bypass** | GKE Autopilot enforces security restrictions (no privileged pods, no hostPath mounts), but certain workload configurations can bypass these guardrails through pod mutation, init containers, or sidecar injection mechanisms | GKE Autopilot with specific workload types |

### §9-2. Cross-Tenant Container Isolation Failure

In multi-tenant Kubernetes deployments, tenants share nodes and often share control plane components. Container escape or privilege escalation in one tenant's workload can cascade to all tenants.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Shared kernel container escape → cross-tenant access** | A container escape vulnerability (§1) exploited on a shared node provides access to all pods co-located on that node, regardless of namespace or tenant. In multi-tenant clusters, this means access to other tenants' data, credentials, and workloads | Multi-tenant cluster with shared node pools; any container escape vulnerability |
| **AI platform cross-tenant escape** | Researchers escaped from isolated customer containers on managed AI platforms (Replicate, Hugging Face) by exploiting container toolkit vulnerabilities (§1-3) and EKS misconfigurations. Post-escape, they accessed other customers' data — private repositories, models, datasets, and proprietary source code from thousands of organizations. On one platform, Redis task queue credentials led to cluster-wide access with 700+ visible nodes | AI inference platforms running multi-tenant GPU workloads; NVIDIA Container Toolkit vulnerability; EKS misconfigurations |
| **Namespace-based isolation inadequacy** | Kubernetes namespaces provide only API-level logical separation — they do not provide kernel-level, network-level, or storage-level isolation. Attackers who compromise a pod in one namespace can access pods in all namespaces through default networking, shared node access, or cluster-scoped RBAC bindings | Namespace-as-tenant model without additional isolation (NetworkPolicies, node isolation, pod security) |

---

## §10. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Attack Chain Example |
|---|---|---|---|
| **Single Container Escape** | Any container runtime | §1, §1-4 | Malicious image exploits runc mount race (§1-1) → host filesystem access → persistent backdoor |
| **Privileged Container → Node Takeover** | Kubernetes/Docker with misconfig | §2 | Privileged pod + Docker socket mount (§2-1) → create new privileged container → host root |
| **Pod Compromise → Cluster Takeover** | Kubernetes | §3, §4, §8 | Application vuln → compromised pod → overpermissioned SA token (§3-4) → cluster-admin → all secrets |
| **Unauthenticated Cluster Compromise** | Kubernetes with Ingress NGINX | §4-1 | IngressNightmare annotation injection → NGINX RCE → SA token → cluster-wide secret exfiltration |
| **Build Pipeline Compromise** | CI/CD with container builds | §1-5, §6 | Malicious Dockerfile in PR → BuildKit race condition → host access during build → credential theft |
| **Supply Chain → Mass Compromise** | Docker Hub + automated deployments | §6, §7 | Typosquatted base image → cryptocurrency miner → thousands of derivative deployments affected |
| **Monitoring Tool → Silent RCE** | Kubernetes with Prometheus/Datadog | §3-1 | Compromised monitoring pod with nodes/proxy GET → WebSocket exec in any pod → no audit trail |
| **Cloud Identity Escalation** | EKS/AKS/GKE | §8-2, §9 | Pod SSRF → IMDS credential theft → IAM escalation → S3/RDS access → data exfiltration |
| **Cross-Tenant AI Platform Breach** | Multi-tenant GPU cluster | §1-3, §9-2 | NVIDIA toolkit escape → host access → Redis credentials → all tenants' models and data |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 (runc mount race) | CVE-2025-31133 (runc) | Container escape via /dev/null symlink → host procfs write; high severity |
| §1-1 (runc mount race) | CVE-2025-52565 (runc) | Container escape via /dev/console bind-mount race |
| §1-1 (runc LSM redirect) | CVE-2025-52881 (runc) | LSM label write redirect → arbitrary procfs write; bypass SELinux/AppArmor |
| §1-2 (FD leak) | CVE-2024-21626 (runc, "Leaky Vessels") | Host filesystem access via leaked /proc/self/exe FD; CVSS 8.6; affects Docker, Kubernetes globally |
| §1-3 (OCI hook env) | CVE-2025-23266 (NVIDIA CTK, "NVIDIAScape") | Minimal Dockerfile → host root; CVSS 9.0; GPU-enabled cloud environments |
| §1-3 (OCI hook TOCTOU) | CVE-2024-0132 (NVIDIA CTK) | Container → host takeover; CVSS 9.0; demonstrated on Replicate, Hugging Face |
| §1-4 (eBPF) | CVE-2021-3490, CVE-2021-31440 | eBPF verifier bypass → kernel memory access → container escape |
| §1-4 (cgroup) | CVE-2022-0492 | cgroup release_agent → host code execution; still exploitable on cgroups v1 |
| §1-5 (BuildKit) | CVE-2024-23651, 23652, 23653 ("Leaky Vessels") | Build-time container escape; CVSS 8.7–9.8 |
| §1-5 (Buildah) | CVE-2024-1753 | Mount source symlink → host filesystem access during build; CVSS 8.6 |
| §3-1 (Windows log query) | CVE-2024-9042 | PowerShell command injection on Windows nodes via log query API |
| §4-1 (IngressNightmare) | CVE-2025-1974, 1097, 1098, 24514 | RCE → cluster-wide secrets; CVSS 9.8 for admission-controller RCE; broad cloud exposure reported |
| §4-3 (gitRepo) | CVE-2024-10220 | Node-level code execution via Git hooks; CVSS 8.1 |
| §6-1 (supply chain) | CVE-2024-3094 (XZ Utils) | Backdoored base images propagating through Docker Hub; CVSS 10.0 |
| §9-2 (cross-tenant) | Wiz/Palo Alto research (2024–2025) | AI platform multi-tenant escape; access to thousands of orgs' data |

---

## Detection Tools

### Offensive / Pentesting

| Tool | Target Scope | Core Technique |
|---|---|---|
| **CDK** (Go, open-source) | Container escape, Kubernetes | Automated exploit collection: cgroup release_agent, Docker socket, capability abuse, mount escapes, eBPF |
| **Peirates** (Go, open-source) | Kubernetes cluster | SA token theft, RBAC enumeration, pod escape, secret extraction, node pivot |
| **BOtB** (Go, open-source) | Container breakout assessment | Common container vulns, metadata service endpoints, UNIX socket discovery |
| **deepce** (Shell, open-source) | Docker/container enumeration | Privilege escalation detection, capability enumeration, mounted socket discovery |
| **kube-hunter** (Python, open-source) | Kubernetes cluster | Remote/internal scanning: exposed APIs, RBAC misconfigs, network policy gaps |
| **badPods** (YAML manifests) | Kubernetes pod privileges | 8 pod configurations × 8 resource types: systematic privilege escalation testing |
| **MTKPI** (Container image) | Kubernetes pentest | Multi-tool image bundling CDK, Peirates, kubectl, and network tools for in-cluster testing |

### Defensive / Detection

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Kubescape** (Go, open-source) | Kubernetes misconfiguration | NSA/CISA framework compliance scanning, RBAC analysis, network policy validation |
| **Trivy** (Go, open-source) | Image/filesystem/cluster | CVE scanning for OS packages, language deps, IaC misconfigs, Kubernetes manifests |
| **Grype** (Go, open-source) | Container images | SBOM-based vulnerability matching for container images and filesystems |
| **Falco** (C++/Go, CNCF) | Runtime threat detection | eBPF/kernel module syscall monitoring: container escape attempts, privilege escalation, shell spawning |
| **Tetragon** (Go, Cilium) | Runtime enforcement | eBPF-based kernel-level security observability: process tracing, file access monitoring, network visibility |
| **Inspektor Gadget** (Go, open-source) | Container debugging/security | eBPF-based container analysis: syscall tracing, network monitoring, runc vulnerability detection |
| **KubeAudit** (Go, open-source) | Kubernetes manifest audit | Static analysis of pod specs for security misconfigurations: capabilities, hostPath, privileged mode |
| **Kubebench** (Go, open-source) | CIS Benchmark compliance | CIS Kubernetes Benchmark validation for control plane and node configurations |

---

## Summary: Core Principles

### 1. The Shared Kernel Is the Root Cause

The fundamental property that makes container escape a persistent threat class is the shared kernel architecture. Unlike virtual machines — which isolate workloads at the hypervisor level with separate kernel instances — containers share a single Linux kernel with the host and all other containers. Every kernel vulnerability is a potential container escape. The eBPF subsystem, cgroup mechanisms, namespace implementation bugs, and filesystem handlers all provide escape primitives that no amount of runtime hardening can fully eliminate. This architectural reality means that container security is inherently probabilistic: it depends on the absence of exploitable kernel bugs, which history demonstrates is an unreliable assumption.

### 2. The Initialization Boundary Is Structurally Fragile

A disproportionate number of container escape vulnerabilities (the runc mount races, FD leaks, OCI hook exploitation) occur during container initialization — the brief period when the runtime transitions from host-context setup to container-context execution. This boundary is structurally fragile because the runtime must perform privileged operations (mounting filesystems, setting up devices, executing hooks) while simultaneously constraining the environment for the container process. Race conditions, leaked handles, and inherited environment variables at this boundary have produced critical vulnerabilities repeatedly across multiple runtimes and toolkits, and the pattern shows no sign of being solved within the current OCI runtime architecture.

### 3. Orchestration Amplifies Individual Escapes Into Systemic Compromise

Kubernetes transforms a single container compromise into a cluster-wide threat through three mechanisms: (a) default network connectivity between all pods, (b) auto-mounted service account tokens with frequently overpermissioned RBAC, and (c) admission controllers and extension points that process untrusted input with elevated privileges. The IngressNightmare vulnerability chain demonstrates this perfectly — a single annotation injection achieves unauthenticated RCE in a pod that happens to have cluster-wide secret access, instantly escalating from a configuration parsing flaw to full cluster takeover. The `nodes/proxy GET` permission being "working as intended" while providing silent RCE in any pod illustrates that the Kubernetes authorization model has design-level gaps that cannot be addressed through patching alone.

### 4. Structural Solutions Require Architectural Changes

Incremental fixes (patching individual runc races, fixing individual NGINX annotation parsers) address symptoms but not root causes. Structural solutions include:

- **Hardware-isolated containers** (Kata Containers, Firecracker, gVisor): Replace the shared kernel with per-workload kernels or system call interception, eliminating the kernel-level escape surface at the cost of performance and compatibility.
- **Capability-based authorization**: Replace broad Linux capabilities and Kubernetes RBAC verbs with fine-grained, non-composable permission tokens that cannot be combined into escalation paths.
- **Immutable admission policies**: Move security-critical admission decisions from in-cluster webhooks (that can be crashed, bypassed, or injected into) to external, tamper-proof policy engines.
- **Zero-trust pod networking**: Default-deny network policies with identity-based (not IP-based) authentication, eliminating the default-open lateral movement surface.
- **Ambient mesh architectures**: Istio Ambient Mesh removes sidecar containers from the trust boundary, running mTLS termination in a node-level ztunnel agent that is not co-located with (and therefore not exploitable from) application containers.

The fundamental tension is that each structural solution imposes operational friction: hardware isolation reduces density and increases cost; fine-grained authorization increases configuration complexity; default-deny networking breaks applications that rely on service discovery. The art of container defense is selecting the isolation model appropriate to the threat model — not treating all containers as equally trustworthy.

---

## References

- [Sysdig: "New runc Vulnerabilities Allow Container Escape: CVE-2025-31133, CVE-2025-52565, CVE-2025-52881"](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities)
- [CNCF: "runc Container Breakout Vulnerabilities: A Technical Overview"](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [Wiz: "Leaky Vessels: Deep Dive on Container Escape Vulnerabilities"](https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities)
- [Wiz: "IngressNightmare: CVE-2025-1974"](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- [Wiz: "NVIDIAScape: CVE-2025-23266"](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)
- [Datadog Security Labs: "Attacking and Securing Cloud Identities in Managed Kubernetes"](https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/)
- [Datadog Security Labs: "IngressNightmare Vulnerabilities Overview and Remediation"](https://securitylabs.datadoghq.com/articles/ingress-nightmare-vulnerabilities-overview-and-remediation/)
- [Edera: "Kubernetes nodes/proxy RCE: When Monitoring Becomes an Attack Vector"](https://edera.dev/stories/your-monitoring-stack-just-became-a-rce-vector-a-deep-dive-into-the-kubernetes-nodes-proxy-rce)
- [Akamai: "Command Injection in Kubernetes Log Query (CVE-2024-9042)"](https://www.akamai.com/blog/security-research/kubernetes-log-query-rce-windows)
- [Bishop Fox: "Bad Pods: Kubernetes Pod Privilege Escalation"](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)
- [SentinelOne: "Climbing The Ladder: Kubernetes Privilege Escalation"](https://www.sentinelone.com/blog/climbing-the-ladder-kubernetes-privilege-escalation-part-1/)
- [Unit42: "Container Escape Techniques in Cloud Environments"](https://unit42.paloaltonetworks.com/container-escape-techniques/)
- [Unit42: "Mitigating RBAC-Based Privilege Escalation in Popular Kubernetes Platforms"](https://unit42.paloaltonetworks.com/kubernetes-privilege-escalation/)
- [Praetorian: "Exploiting Kubernetes through Operator Injection"](https://www.praetorian.com/blog/exploiting-kubernetes-through-operator-injection/)
- [CrowdStrike: "Exploiting CVE-2021-3490 for Container Escapes"](https://www.crowdstrike.com/en-us/blog/exploiting-cve-2021-3490-for-container-escapes/)
- [USENIX Security: "Cross Container Attacks: The Bewildered eBPF on Clouds"](https://www.usenix.org/system/files/usenixsecurity23-he.pdf)
- [Aqua Security: "Linux Kernel Vulnerability: Escaping Containers by Abusing Cgroups"](https://www.aquasec.com/blog/new-linux-kernel-vulnerability-escaping-containers-by-abusing-cgroups/)
- [Aqua Security: "Leveraging Kubernetes RBAC to Backdoor Clusters"](https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/)
- [Docker: "Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby"](https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/)
- [InstaTunnel: "The Sidecar Siphon: Exploiting Identity Leaks in Service Mesh Architectures"](https://instatunnel.my/blog/the-sidecar-siphon-exploiting-identity-leaks-in-service-mesh-architectures)
- [Kubernetes: "Ingress-nginx CVE-2025-1974: What You Need to Know"](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- [Kubernetes: "CVE-2024-10220: Arbitrary Command Execution through gitRepo Volume"](https://discuss.kubernetes.io/t/security-advisory-cve-2024-10220-arbitrary-command-execution-through-gitrepo-volume/30571)
- [Microsoft: "Understanding the Threat Landscape for Kubernetes and Containerized Assets"](https://www.microsoft.com/en-us/security/blog/2025/04/23/understanding-the-threat-landscape-for-kubernetes-and-containerized-assets/)
- [USENIX: "Exploring and Exploiting the Resource Isolation Attack Surface of WebAssembly Containers"](https://arxiv.org/html/2509.11242)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
