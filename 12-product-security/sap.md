# SAP Enterprise Platform — Vulnerability Mutation Taxonomy

---

## Classification Structure

SAP's enterprise platform presents one of the most complex attack surfaces in the software industry. Unlike web-only applications, SAP exposes a multi-layered architecture spanning proprietary binary protocols (RFC, Diag, Router), a custom HTTP stack (ICM), application servers in two distinct technology stacks (ABAP and Java), an in-memory database (HANA), and an extensive web frontend layer (Fiori/UI5, OData). Each layer introduces its own class of vulnerability mutations, and many of the most severe exploit chains combine weaknesses across these layers.

This taxonomy classifies SAP vulnerability mutations along three axes:

- **Axis 1 — Mutation Target (Primary)**: The structural component or protocol being attacked. This axis organizes the main body of the document into ten top-level categories (§1–§10), each targeting a different architectural surface of the SAP platform.

- **Axis 2 — Security Boundary Violation (Cross-cutting)**: The type of security boundary that each mutation bypasses. Every technique falls into one of the following discrepancy types, which cut across all categories:

| Code | Boundary Violation Type | Description |
|------|------------------------|-------------|
| **V-AUTH** | Authentication Bypass | No credentials required; attacker is unauthenticated |
| **V-AUTHZ** | Authorization Bypass | Valid credentials present but insufficient privilege checks |
| **V-INJ** | Input Validation Failure | Injection, traversal, or format manipulation through unsanitized input |
| **V-DESYNCH** | Parser/Protocol Mismatch | Desynchronization between two processing components |
| **V-CONFIG** | Configuration Weakness | Exploitable defaults, open ACLs, or hardcoded credentials |
| **V-MEM** | Memory Safety Violation | Buffer overflow, heap corruption, or NULL pointer dereference |

- **Axis 3 — Attack Scenario (Mapping)**: The operational impact context — where and how the mutation is weaponized in real-world campaigns.

| Scenario | Description |
|----------|-------------|
| **S-RCE** | Unauthenticated remote code execution |
| **S-PRIVESC** | Authenticated privilege escalation to SAP_ALL or OS-level |
| **S-LATERAL** | Lateral movement (e.g., SolMan → satellite systems) |
| **S-EXFIL** | Data exfiltration (financial records, PII, credentials) |
| **S-SUPPLY** | Supply chain compromise via transport system or update pipeline |
| **S-PERSIST** | Persistent access through webshells, backdoors, or ABAP programs |
| **S-CACHE** | Cache poisoning, session hijacking, or response manipulation |
| **S-DOS** | Denial of service through crash or resource exhaustion |

---

## §1. Authentication & Session Management Bypass

Authentication failures in SAP are disproportionately severe because a single SAP system typically manages financial data, supply chain operations, and HR records for an entire enterprise. Missing authentication checks in SAP have repeatedly yielded CVSS 9.8–10.0 scores because they grant unauthenticated attackers administrative-level access.

### §1-1. Missing Authentication Checks in Web Endpoints

The most critical SAP vulnerability pattern: entire web-facing components deployed with no authentication check whatsoever on sensitive endpoints.

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **LM Configuration Wizard bypass** | The Configuration Wizard in NetWeaver AS Java exposes administrative operations (user creation, OS command execution) with zero authentication enforcement | V-AUTH | NetWeaver AS Java with LM Configuration Wizard enabled (CVE-2020-6287, CVSS 10.0) |
| **Visual Composer metadata upload** | The `/developmentserver/metadatauploader` endpoint accepts arbitrary file uploads without proper authorization (per SAP/NVD: "not protected with a proper authorization"). The practical result is unauthenticated exploitation, though the root cause is inadequate authorization rather than a complete absence of authentication infrastructure | V-AUTH | Visual Composer component installed on NetWeaver 7.x (CVE-2025-31324, CVSS 10.0) |
| **Solution Manager EEM servlet** | The `/EemAdminService/EemAdmin` SOAP endpoint permits unauthenticated requests to enumerate SMDAgents, send HTTP requests (SSRF), and execute OS commands on connected agents | V-AUTH | SAP Solution Manager 7.2 with connected SMDAgents (CVE-2020-6207, CVSS 10.0) |
| **BusinessObjects REST endpoint** | When SSO is enabled for Enterprise authentication, a REST endpoint allows unauthenticated retrieval of logon tokens, granting full platform access | V-AUTH | SAP BO BI Platform with SSO enabled (CVE-2024-41730, CVSS 9.8) |
| **Invoker Servlet** | The J2EE Invoker Servlet allows direct invocation of any registered servlet over HTTP without authentication or authorization controls | V-AUTH | NetWeaver AS Java with Invoker Servlet enabled (CVE-2010-5326) |

The Invoker Servlet is particularly notable: patched in 2010, it remained widely exploitable for over a decade due to persistent misconfigurations in production systems. US-CERT issued a dedicated alert in 2016 after confirming active exploitation against critical infrastructure.

### §1-2. Default and Hardcoded Credentials

SAP systems ship with well-known default accounts that are frequently left unchanged in production environments.

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **SAP* superuser** | The SAP* user exists in every ABAP client. Per SAP documentation, the password is set to the master password specified during installation. However, if SAP* does not exist in a given client (e.g., new clients copied from client 000), the system falls back to the hard-coded password `PASS`. SAP* cannot be fully deleted — only locked or password-changed. | V-CONFIG | ABAP systems where SAP* password unchanged or fallback `PASS` applies |
| **DDIC / EARLYWATCH accounts** | Standard installation users created in client 000 with documented default passwords | V-CONFIG | Unconfigured post-installation systems |
| **TMSADM transport user** | System user created during TMS configuration. Per SAP documentation, the password is set to the master password from installation — not a universally "well-known" default. However, in practice it is frequently weak or unchanged, and grants RFC access to transport management operations | V-CONFIG | ABAP systems with TMS configured; TMSADM password weak or unchanged |
| **SQL Anywhere Monitor hardcoded credentials** | Administrative credentials baked directly into the monitoring database, never intended to be changed by users. Per NVD, this enables arbitrary code execution — the impact extends beyond administrative access to potential full system compromise | V-CONFIG | SAP SQL Anywhere Monitor 17.0 (CVE-2025-42890, CVSS 10.0) |

The TMSADM case demonstrates how a seemingly low-risk system account can enable critical attacks: with its known credentials, an adversary can remotely invoke RFC functions to read/delete files or execute arbitrary ABAP code.

### §1-3. SSO and Token Manipulation

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **SAP Logon Ticket forgery** | Crafting or replaying SAP Logon Tickets to impersonate arbitrary users when ticket validation is weak or signing keys are compromised | V-AUTH | Systems relying on Logon Tickets without SNC enforcement |
| **Kernel-level authentication bypass** | Crafting special requests that exploit design flaws in the SAP kernel's authentication processing to claim arbitrary identities | V-AUTH | SAP kernel ABAP releases in maintenance (CVE-2021-27610, CVSS 9.0) |
| **HANA user impersonation** | An authenticated user exploits a privilege escalation flaw to switch to another user context, potentially gaining administrative access | V-AUTHZ | SAP HANA database (CVE-2026-0492, CVSS 8.8) |

---

## §2. Code Injection & Dynamic Execution

SAP's ABAP runtime supports powerful dynamic code generation constructs (`INSERT REPORT`, `GENERATE SUBROUTINE POOL`, `SUBMIT ... VIA JOB`) that, when reachable through improperly validated RFC function modules, allow injected ABAP code to execute with the privileges of the host system.

### §2-1. ABAP Code Injection via RFC

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Dynamic ABAP generation injection** | Crafted input supplied to RFC-enabled function modules is passed directly to `INSERT REPORT` or `GENERATE SUBROUTINE POOL` without sanitization, allowing arbitrary ABAP execution | V-INJ | Low-privileged account with S_RFC authorization (CVE-2025-42957, CVSS 9.9) |
| **Report generation injection** | Vulnerable `/SLOAP/GEN_MODULE_REPORT` function module allows code injection through parameter manipulation during report generation | V-INJ | S/4HANA with SLT/DMIS components (CVE-2025-27429) |
| **Transport import injection** | BDLFUPIMP table entries with unvalidated `IS_DEFAULT` parameter enable code injection during Solution Manager import operations | V-INJ | SAP Solution Manager (CVE-2025-42887, CVSS 9.9) |

The CVE-2025-42957 attack chain is devastating: with a single low-privileged account and one RFC call, an attacker can create SAP_ALL superuser accounts, manipulate business data directly in the database, exfiltrate hashed passwords, and gain OS-level access. SecurityBridge confirmed wild exploitation in September 2025.

### §2-2. OS Command Injection

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Gateway ACL command execution** | When SAP Gateway ACLs are misconfigured (e.g., `HOST=*` in `reginfo`/`secinfo`), unauthenticated attackers can invoke OS commands through the Gateway service. Note: the actual default ACL behavior depends on SAP kernel version and applied security notes — `HOST=*` is a known misconfiguration pattern but not necessarily the out-of-the-box default in all versions | V-CONFIG | SAP Gateway on ports TCP/3300-3399 with permissive ACLs |
| **SMDAgent command execution** | Unauthenticated SOAP requests to Solution Manager's EEM endpoint relay OS commands to connected SMDAgents, executing as the `daaadm` user | V-AUTH | Connected SMDAgents (see §1-1) |
| **Wily Introscope JNLP injection** | Malicious JNLP files crafted via a public-facing URL trigger command execution when processed by the Introscope server | V-AUTH | SAP Wily Introscope Enterprise Manager (CVE-2026-0500, CVSS 9.6) |

### §2-3. SQL Injection

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **S/4HANA General Ledger SQL injection** | Authenticated attackers execute arbitrary SQL queries through the Financials General Ledger module | V-INJ | SAP S/4HANA Financials (CVE-2026-0501, CVSS 9.9) |
| **Open SQL / Native SQL injection in custom code** | Custom ABAP programs using string concatenation in `SELECT` statements instead of parameterized queries | V-INJ | Custom Z-programs on any ABAP system |

---

## §3. Insecure Deserialization

Java deserialization vulnerabilities in SAP NetWeaver AS Java represent the highest-severity vulnerability class, with multiple CVSS 10.0 entries. The attack surface spans multiple protocols (HTTP, RMI-P4) and components (Visual Composer, application server core).

### §3-1. Java Object Deserialization via Network Protocols

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **RMI-P4 deserialization** | Malicious serialized Java objects submitted to the P4 protocol listener (port 5NN04) are deserialized without validation, enabling arbitrary OS command execution through gadget chains | V-AUTH | NetWeaver AS Java with P4 port exposed (CVE-2025-42944, CVSS 10.0) |
| **Visual Composer deserialization chain** | After initial file upload (§1-1), chained deserialization vulnerability enables elevated code execution through crafted serialized payloads | V-AUTH | Visual Composer + NetWeaver AS Java (CVE-2025-42999) |

The RMI-P4 attack is particularly dangerous because the P4 protocol typically listens on a well-known port pattern (5NN04 where NN = system number), the attack requires zero authentication, and exploitation leverages gadget chains built from standard Java libraries or SAP-specific classes bundled in the application server.

SAP's October 2025 comprehensive patch implemented a JVM-wide deserialization filter to block known dangerous classes, representing a shift from endpoint-level to system-wide deserialization defense.

### §3-2. XML-Based Deserialization / Entity Injection

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **IGS XMLCHART XXE** | The XMLCHART endpoint in Internet Graphics Server accepts XML input without entity validation, enabling file read and denial of service as the SAP admin user | V-AUTH | SAP IGS 7.20–7.53 (CVE-2018-2392, CVE-2018-2393) |
| **Web service XXE** | XML parsers in various NetWeaver web services (K2EE) process external entities without restriction | V-INJ | NetWeaver AS Java web services |

---

## §4. HTTP Request Smuggling & Protocol Desynchronization

SAP's Internet Communication Manager (ICM) implements HTTP processing through a shared-memory architecture using Memory Pipes (MPI) for inter-process communication with ABAP and Java work processes. This architecture creates unique desynchronization attack surfaces not found in standard web servers.

### §4-1. Memory Pipe Desynchronization (ICMAD)

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Content-Length desync** | Crafted HTTP requests with manipulated Content-Length headers cause the ICM and backend work processes to disagree on message boundaries, desynchronizing the MPI buffer | V-DESYNCH | Any proxy in default config between ICM and clients (CVE-2022-22536, CVSS 10.0) |
| **Transfer-Encoding desync** | Injecting `Transfer-Encoding: chunked` headers causes parsing disagreement between ICM and backend ABAP/Java processes | V-DESYNCH | SAP NetWeaver with ICM |
| **Response buffer hijacking** | By escalating desync errors, attackers manipulate out-of-bounds MPI buffer address pointers, achieving a Write-What-Where condition for session hijacking | V-DESYNCH | ICM data buffer manipulation |

A critical characteristic of ICMAD: exploitation requires only a **single HTTP request** when a proxy with default configuration sits between the client and ICM. The attacker can prepend arbitrary data to a victim's request, enabling:
- Function execution while impersonating the victim
- Web cache poisoning with malicious payloads
- Response splitting for account hijacking

### §4-2. ICM Request Smuggling Variants

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **ACL bypass via desync** | Request smuggling bypasses SAP Gateway ACL checks by injecting requests that the ICM processes differently from the backend authorization layer | V-DESYNCH | SAP NetWeaver with Gateway ACL |
| **Inter-process desync primitives** | Advanced techniques exploiting IPC mechanisms between ICM and work processes to create new desynchronization primitives beyond classic HRS | V-DESYNCH | SAP NetWeaver ABAP/Java dual-stack |

---

## §5. Directory Traversal & Unrestricted File Operations

Path traversal and unrestricted file upload vulnerabilities in SAP are especially dangerous because they often directly enable webshell deployment (§5-2), which has become the primary persistence mechanism in observed APT campaigns against SAP systems.

### §5-1. Path Traversal

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **SAP Print Service directory traversal** | Insufficient validation of user-supplied path information in SAPSprint allows unauthenticated attackers to traverse directories and overwrite critical system files | V-AUTH + V-INJ | SAPSprint 8.00/8.10 (CVE-2025-42937, CVSS 9.8) |
| **NetWeaver AS Java scheduler traversal** | Path traversal in the scheduler UI JavaScript loading mechanism (`/scheduler/ui/js/ffffffffbca41eb4/...`) | V-INJ | NetWeaver AS Java |
| **Classic `../` traversal in web services** | Multiple web-facing components fail to filter `../`, `..\`, or URL-encoded path traversal sequences | V-INJ | Various SAP components |
| **Double encoding bypass** | Multiple encoding layers (`%252e%252e%252f`) bypass basic input filters that only decode once | V-INJ | SAP web endpoints with single-decode validation |
| **SAP Portal directory traversal** | Traversal through the SAP Enterprise Portal enables reading arbitrary files from the application server | V-INJ | SAP Enterprise Portal |

### §5-2. Unrestricted File Upload & Webshell Deployment

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Metadata Uploader arbitrary upload** | The Visual Composer metadatauploader endpoint permits arbitrary file upload (including JSP webshells) without authentication | V-AUTH | CVE-2025-31324 (see §1-1) |
| **SRM unrestricted file upload** | Lack of file type/content verification in SAP SRM allows authenticated upload of executables or scripts | V-INJ | SAP SRM SRMNXP01 100/150 (CVE-2025-42910) |
| **Webshell persistence patterns** | Deployed webshells (`helper.jsp`, `cache.jsp`, randomized 8-letter names like `ssonkfrd.jsp`) execute as `<sid>adm` OS user with full SAP resource access | V-AUTH | Post-exploitation of §5-2 upload vectors |

In observed APT campaigns (2025), Chinese cyber-espionage units (UNC5221, UNC5174, CL-STA-0048) used CVE-2025-31324 to deploy JSP webshells, followed by advanced post-exploitation frameworks including Brute Ratel and Heaven's Gate technique for cross-architecture code execution (32/64-bit) while evading detection.

---

## §6. Server-Side Request Forgery (SSRF) & Outbound Request Manipulation

SAP's server-side components frequently make outbound HTTP requests for integration purposes (RFC-to-HTTP, document rendering, agent communication), creating multiple SSRF surfaces.

### §6-1. SSRF in Application Services

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Adobe Document Service SSRF** | Administrative users can send crafted requests through the Adobe Document Service to read/modify arbitrary files or cause service unavailability | V-INJ | NetWeaver with Adobe Document Service (CVE-2024-47578, CVSS 9.1) |
| **Solution Manager agent SSRF** | The EEM servlet's missing authentication allows unauthenticated SSRF through SMDAgent HTTP request relay functionality | V-AUTH | SAP Solution Manager (see §1-1, CVE-2020-6207) |
| **K2EE web service SSRF** | Multiple SSRF issues in NetWeaver Java web services allow internal network scanning and metadata access | V-INJ | NetWeaver AS Java |
| **RFC-based SSRF** | RFC function modules that accept URL parameters can be abused to make arbitrary outbound requests from the SAP server | V-AUTHZ | ABAP systems with exposed RFC modules |

### §6-2. Web Dispatcher and Proxy-Level SSRF

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Web Dispatcher XSS-to-SSRF chain** | A cross-site scripting vulnerability in SAP Web Dispatcher can be leveraged for server-side request forgery, leading to remote code execution | V-INJ | SAP Web Dispatcher (CVE-2024-47590, CVSS 8.8) |
| **RFC Information Disclosure** | Information Disclosure through Remote Function Call allows extraction of sensitive data from ABAP systems | V-AUTHZ | NetWeaver ABAP (CVE-2024-54198, CVSS 8.5) |

---

## §7. Memory Corruption

Low-level memory corruption vulnerabilities in SAP's kernel binaries (`disp+work.exe`, `libsapcrypto.so`, SAPCAR) and protocol parsers provide pathways to denial of service and, in some cases, remote code execution. These are technically harder to exploit than web-layer flaws but can bypass all application-level controls.

### §7-1. Protocol Parser Corruption

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **RFC logon material corruption** | Malformed RFC packets with specially crafted logon material trigger memory corruption in the kernel binary's parser, potentially leading to authentication bypass or code execution | V-MEM | SAP kernel RFC handler |
| **Dispatcher integer underflow** | SAP Dispatcher packet with valid header but undersized total length causes negative value in subtraction, corrupting `DpRTmPrepareReq` memory structures | V-MEM | `disp+work.exe` (CVE-2012-2611) |
| **Logon Ticket NULL pointer dereference** | Malformed SAP Logon or SAP Assertion Tickets trigger NULL pointer dereference in the kernel, causing process termination | V-MEM | SAP kernel 7.22–9.16 (CVE-2025-42902) |

### §7-2. Library and Tool Corruption

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **CommonCryptoLib memory corruption** | The `sec1_gss_import_name()` function in `libsapcrypto.so` trusts the incoming size parameter without validation, enabling heap manipulation | V-MEM | SAP CommonCryptoLib |
| **SAPCAR heap buffer overflow** | The SAPCAR archiving tool uses the last two bytes of file metadata as a size field without validation, copying arbitrary data into a fixed-length heap buffer | V-MEM | SAPCAR (CVE-2017-8852) |
| **IGS memory corruption** | Memory corruption in Internet Graphics Server ABAP IGS service through crafted input | V-MEM | SAP NetWeaver ABAP IGS |

---

## §8. Authorization & Privilege Escalation

SAP's authorization model is based on Authorization Objects — compound permission checks that evaluate multiple fields simultaneously. Misconfigurations in these objects, combined with overly permissive RFC access, create systematic privilege escalation pathways.

### §8-1. Authorization Object Abuse

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **S_RFC wildcard assignment** | Setting `RFC_NAME = *` in the S_RFC authorization object grants unrestricted access to all remote-enabled function modules, enabling table modification, user creation, password resets, and business data manipulation | V-AUTHZ | Any ABAP system with S_RFC wildcard |
| **S_DEVELOP in production** | When S_DEVELOP authorization is not properly restricted in production, developers or technical users can create/modify ABAP programs at runtime | V-AUTHZ | Production ABAP systems |
| **Authorization buffer exploitation** | Manipulating the in-memory authorization buffer to temporarily elevate privileges before checks are performed | V-AUTHZ | ABAP systems with stale buffer states |
| **RFC_READ_TABLE abuse** | With S_RFC access and insufficiently restricted `RFC_READ_TABLE` calls, sensitive database tables (including payroll, HR, financial) can be read remotely. Actual scope depends on S_RFC authorization values, S_TABU_DIS table group restrictions, and whether SAP Notes restricting RFC_READ_TABLE have been applied | V-AUTHZ | ABAP systems with permissive S_RFC and unrestricted RFC_READ_TABLE |

### §8-2. Transaction Code Privilege Escalation

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **High-privilege T-Code execution** | Enumerating and executing transaction codes (SE37, SE38, SM69, SE16) that should be restricted to administrators | V-AUTHZ | Insufficient transaction code restrictions |
| **SAP_ALL profile acquisition** | Exploiting vulnerable function modules to escalate privileges to SAP_ALL — the highest-privileged profile in ABAP systems | V-AUTHZ | SAP Business Warehouse function modules |

### §8-3. Cross-System Privilege Escalation

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Solution Manager to satellite** | Compromising Solution Manager grants access to all connected satellite systems through trusted RFC connections and SMDAgent infrastructure | V-AUTHZ | SAP Solution Manager with connected landscapes |
| **HANA database user switching** | Authenticated HANA users exploit privilege escalation flaw to switch to another user, potentially gaining administrative access | V-AUTHZ | SAP HANA database (CVE-2026-0492) |
| **RFC callback attacks** | Exploiting trusted RFC connections between SAP systems to pivot from a compromised system to connected targets | V-AUTHZ | SAP landscapes with RFC trust relationships |

---

## §9. Network Protocol Exploitation

SAP exposes proprietary binary protocols on well-known port patterns that are often reachable from internal networks. External exposure studies (e.g., Shodan/Censys scans cited in security research) have reported thousands of Internet-exposed SAP services, though exact numbers vary by methodology and time period.

### §9-1. RFC (Remote Function Call) Protocol

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **RFC Gateway ACL bypass** | Bypassing Gateway ACL restrictions from external systems to access the Gateway directly for known attacks including command execution | V-CONFIG | SAP Gateway TCP/3300-3399 with permissive ACLs |
| **RFC user enumeration** | Exposed RFC functions allow remote enumeration of valid user accounts and server request capabilities | V-AUTHZ | RFC Gateway exposed to network |
| **RFC-to-RCE exploit chain** | Combining RFC authentication, function module discovery, and code injection for complete system compromise from initial RFC access | V-INJ + V-AUTHZ | RFC interface on ABAP systems |

### §9-2. SAProuter

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **SAProuter pivoting** | Using SAProuter as a proxy to reach internal SAP systems from external networks, bypassing network segmentation | V-CONFIG | SAProuter with permissive route tables |
| **SAProuter information disclosure** | Enumerating internal SAP system topology and port information through SAProuter queries | V-CONFIG | SAProuter accessible from untrusted networks |

### §9-3. Message Server

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Message Server ACL bypass (10KBLAZE)** | Permissive `HOST=*` configuration in Message Server ACL allows anonymous users to register as application servers, redirect user sessions, or intercept traffic | V-CONFIG | SAP Message Server with permissive ACL. Note: the "90% of deployments" estimate originates from the 10KBLAZE research presentation, not from SAP official data — actual prevalence may vary |
| **Internal port exposure** | Message Server internal communication port accessible from client networks, allowing registration of rogue application servers | V-CONFIG | Unsegmented MS internal/public communications |

### §9-4. Diag Protocol

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **SAP GUI credential sniffing** | SAP Diag protocol traffic can be intercepted and decoded to extract user IDs and passwords from "invisible" fields in early session packets | V-CONFIG | Diag connections without SNC encryption |
| **Diag compression attack** | Exploiting the Diag protocol's compression mechanisms to inject or manipulate application-layer data | V-DESYNCH | Unencrypted SAP GUI connections |

---

## §10. Client-Side & Web Layer Attacks

SAP's web-facing layer — Fiori Launchpad, SAPUI5 applications, OData services, and Commerce Cloud — introduces standard web vulnerability classes with SAP-specific exploitation contexts.

### §10-1. Cross-Site Scripting (XSS)

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Fiori Launchpad reflected XSS** | Insufficient encoding of user-controlled inputs in the Fiori Launchpad enables reflected XSS, allowing session hijacking and CSRF against SAP backend | V-INJ | SAP Fiori Launchpad (CVE-2022-26101) |
| **SAPUI5 DOM-based XSS** | Dynamic HTML/JavaScript creation in SAPUI5 applications incorporating attacker-controlled values | V-INJ | Custom SAPUI5 applications |
| **Commerce Cloud Swagger UI XSS** | DOM-based XSS in bundled Swagger UI library's explore feature allows unauthenticated code injection from remote sources | V-INJ | SAP Commerce Cloud (CVE-2025-27434, CVSS 8.8) |

### §10-2. OData and API Exposure

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **OData service information disclosure** | Open OData services leak server metadata and sensitive data through GET parameters without proper access controls | V-CONFIG | Exposed Fiori/OData services |
| **PII in URL parameters** | Sensitive data (passwords, email addresses, mobile numbers, coupon codes) included in request URL as query or path parameters, logged in access logs and caches | V-INJ | SAP Commerce Cloud APIs (CVE-2024-33003) |
| **CSRF token bypass** | Disabling CSRF token validation for OData calls weakens session integrity protections | V-CONFIG | Misconfigured NetWeaver Gateway |

### §10-3. BTP and Cloud-Specific Vulnerabilities

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Spring Boot Actuator exposure** | Custom Java applications in SAP BTP implemented with Spring Framework expose debugging/monitoring endpoints through Spring Boot Actuator | V-CONFIG | SAP BTP custom Java applications |
| **Cloud migration transitional gaps** | During RISE migration from on-premise to BTP, security controls on legacy assets and new cloud assets may have coverage gaps | V-CONFIG | Organizations in RISE transition |

---

## §11. Supply Chain & Transport System Manipulation

SAP's Transport Management System (TMS) manages code promotion across development, quality assurance, and production landscapes. Vulnerabilities in this pipeline allow attackers to inject malicious code that passes through quality gates undetected.

### §11-1. Transport Request Tampering

| Subtype | Mechanism | Boundary Violation | Key Condition |
|---------|-----------|--------------------|---------------|
| **Transport status manipulation** | After a transport request is exported but before import, an attacker changes its status from "released" back to "modifiable," enabling payload injection | V-AUTHZ | ABAP Platform (CVE-2021-38178, CVSS 9.1) |
| **Post-quality-gate injection** | Malicious code added to transport requests that have already passed all quality gates, executing upon import into the target system | V-AUTHZ | SAP development landscapes with TMS |
| **Pre-production payload insertion** | Altering transport content just before promotion into production, bypassing all earlier review stages | V-AUTHZ | Multi-system SAP landscapes |

This vulnerability class is uniquely dangerous because it turns SAP's own change management infrastructure into an attack vector. A successful transport injection can deliver malicious ABAP code into production systems with legitimate change management approval records, making forensic detection extremely difficult.

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Example Chain |
|----------|-------------|---------------------------|---------------|
| **S-RCE** (Unauthenticated RCE) | Internet-facing NetWeaver | §1-1 + §3-1, §1-1 + §5-2 | Visual Composer upload → webshell → OS command (CVE-2025-31324) |
| **S-PRIVESC** (Privilege Escalation) | Internal ABAP systems | §2-1 + §8-1 | Low-privilege RFC → ABAP injection → SAP_ALL (CVE-2025-42957) |
| **S-LATERAL** (Lateral Movement) | SolMan → satellite landscapes | §1-1 + §2-2 + §8-3 | SolMan compromise → SMDAgent → satellite OS commands (CVE-2020-6207) |
| **S-EXFIL** (Data Exfiltration) | Any ABAP system | §8-1 + §9-1 | S_RFC wildcard → RFC_READ_TABLE → payroll/financial data |
| **S-SUPPLY** (Supply Chain) | Development landscape | §11-1 + §2-1 | Transport tampering → ABAP injection in production |
| **S-PERSIST** (Persistence) | Compromised NetWeaver | §5-2 + §2-1 | Webshell deployment + ABAP backdoor program |
| **S-CACHE** (Cache Poisoning) | ICM with reverse proxy | §4-1 | MPI desync → response poisoning → credential theft (CVE-2022-22536) |
| **S-DOS** (Denial of Service) | Any exposed component | §7-1, §3-2 | Malformed logon ticket → NULL deref → process crash |

---

## CVE / Bounty Mapping (2020–2026)

| Mutation Combination | CVE / Case | Year | CVSS | Impact |
|---------------------|-----------|------|------|--------|
| §1-1 (LM Config Wizard) | CVE-2020-6287 (RECON) | 2020 | 10.0 | Unauthenticated admin user creation, full system compromise. Exploits appeared 72 hours after patch |
| §1-1 (SolMan EEM) | CVE-2020-6207 | 2020 | 10.0 | Unauthenticated RCE on all connected SMDAgents |
| §4-1 (MPI desync) | CVE-2022-22536 (ICMAD) | 2022 | 10.0 | Single-request cache poisoning, session hijacking, full compromise |
| §1-2 (Hardcoded creds) | CVE-2025-42890 | 2025 | 10.0 | Hardcoded credentials in SQL Anywhere Monitor enabling arbitrary code execution (per NVD). Impact is broader than "admin access" — includes potential for full system compromise via the monitoring database |
| §3-1 (RMI-P4 deser) | CVE-2025-42944 | 2025 | 10.0 | Unauthenticated OS command execution via deserialization |
| §1-1 (Visual Composer) | CVE-2025-31324 | 2025 | 10.0 | Unauthenticated file upload → webshell → RCE. Exploited by Chinese APTs (UNC5221, UNC5174) targeting critical infrastructure |
| §1-1 + §3-1 (Visual Composer chain) | CVE-2025-42999 | 2025 | 9.9 | Deserialization chain following initial file upload |
| §2-1 (ABAP injection) | CVE-2025-42957 | 2025 | 9.9 | Low-privilege → SAP_ALL via ABAP injection through RFC. Wild exploitation confirmed |
| §2-1 (SolMan code inj) | CVE-2025-42887 | 2025 | 9.9 | Authenticated code injection with cross-scope impact |
| §5-1 (Print Service traversal) | CVE-2025-42937 | 2025 | 9.8 | Unauthenticated directory traversal → system file overwrite |
| §1-1 (BO BI SSO bypass) | CVE-2024-41730 | 2024 | 9.8 | Unauthenticated logon token retrieval when SSO enabled |
| §2-2 (Wily Introscope) | CVE-2026-0500 | 2026 | 9.6 | Unauthenticated RCE via malicious JNLP file |
| §2-3 (S/4HANA SQL injection) | CVE-2026-0501 | 2026 | 9.9 | Authenticated arbitrary SQL execution on financial data |
| §11-1 (Transport tamper) | CVE-2021-38178 | 2021 | 9.1 | Supply chain attack through transport request manipulation |
| §6-1 (Adobe Doc SSRF) | CVE-2024-47578 | 2024 | 9.1 | Admin-level SSRF → arbitrary file read/modify |
| §1-3 (Kernel auth bypass) | CVE-2021-27610 | 2021 | 9.0 | Identity claiming → full system access |
| §10-1 (Commerce XSS) | CVE-2025-27434 | 2025 | 8.8 | DOM-based XSS via bundled Swagger UI |
| §6-2 (Web Dispatcher) | CVE-2024-47590 | 2024 | 8.8 | XSS → SSRF → RCE chain |
| §8-3 (HANA privesc) | CVE-2026-0492 | 2026 | 8.8 | User impersonation → admin escalation |
| §7-1 (Logon ticket crash) | CVE-2025-42902 | 2025 | — | NULL pointer deref → process termination |

### Threat Actor Mapping (2025 Campaigns)

| Actor | Target | Technique | §Reference |
|-------|--------|-----------|------------|
| **UNC5221** (China MSS) | Critical infrastructure | CVE-2025-31324 → JSP webshell → Brute Ratel C2 | §1-1 + §5-2 |
| **UNC5174** (China MSS) | Government, manufacturing | CVE-2025-31324 → Heaven's Gate technique | §1-1 + §5-2 |
| **CL-STA-0048** (China MSS) | Energy, defense | Visual Composer chain → persistent access | §1-1 + §3-1 |
| **ShinyHunters / Scattered LAPSUS$** | Broad targeting | Public exploit release (Aug 2025) — "turnkey" compromise | §1-1 |
| **Russian-linked ransomware groups** | Manufacturing | SAP system encryption → 6-week operational shutdown | Multiple |

---

## Detection Tools

### Offensive / Penetration Testing

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **pySAP** (Open source) | SAP proprietary protocols (NI, Diag, Router, MS, RFC, HDB, IGS, SNC, Enqueue) | Scapy-based packet crafting and protocol interaction |
| **Metasploit SAP modules** | RFC Gateway, SAProuter, Dispatcher, Invoker Servlet, IGS | Exploit and auxiliary modules for common SAP attack vectors |
| **SAP-Dissection-plug-in-for-Wireshark** (Open source) | SAP NI, Message Server, Router, Diag, Enqueue, IGS, SNC, HDB protocols | Protocol dissection for traffic analysis and credential extraction |
| **PowerSAP** (Airbus SecLab) | SAP ABAP systems | PowerShell-based SAP assessment tool |
| **SAPGateBreaker** (PoC) | ICM request smuggling | CVE-2022-22536 exploitation demonstrating ACL bypass via desync |
| **SAP_RECON** (PoC) | LM Configuration Wizard | CVE-2020-6287 and CVE-2020-6286 exploitation |
| **HackTricks SAP Methodology** | Comprehensive | Community-maintained SAP pentesting cheat sheet |
| **SAP-Pentest-Cheatsheet** (GitHub) | Web and network layers | Structured SAP penetration testing methodology |

### Defensive / Monitoring

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Onapsis Platform** | Comprehensive SAP security | Real-time vulnerability assessment, threat monitoring, and compliance for on-premise and cloud SAP |
| **Onapsis ICMAD Scanner** (Free) | ICM desync vulnerabilities | Dedicated scanner for CVE-2022-22536 and related ICMAD flaws |
| **Onapsis RECON Scanner** (Free) | RECON vulnerability | Dedicated scanner for CVE-2020-6287 |
| **SecurityBridge** | SAP ABAP security | Real-time threat detection, vulnerability management, and code analysis for ABAP systems |
| **Pathlock** | SAP authorization and access | RFC callback defense, authorization monitoring, Segregation of Duties |
| **Layer Seven Security** | SAP platform assessment | Specialized SAP penetration testing and vulnerability management |

---

## Summary: Core Principles

### Why SAP Is Uniquely Vulnerable

The fundamental property that makes SAP's attack surface so extensive is **architectural heterogeneity combined with deep internal trust**. A single SAP landscape combines:

1. **Proprietary binary protocols** (RFC, Diag, Router) designed for internal use but frequently exposed to networks
2. **A custom HTTP stack** (ICM) with unique memory-sharing architecture not found in standard web servers
3. **Two distinct application server stacks** (ABAP and Java) with different vulnerability profiles
4. **Dynamic code execution primitives** (ABAP's `INSERT REPORT`, `GENERATE SUBROUTINE POOL`) that are architectural features, not bugs
5. **A trust-based inter-system model** where Solution Manager connects to all satellites, RFC connections bridge systems, and transport management moves code across environments

Each of these layers trusts the others implicitly. ICM trusts that incoming requests are well-formed. ABAP work processes trust that RFC parameters are sanitized. Solution Manager agents trust commands from the central server. Transport systems trust that released requests haven't been modified.

### Why Incremental Patches Fail

SAP's patch velocity has increased dramatically — but the fundamental vulnerability production rate remains high because:

- **The protocol surface is vast and proprietary**: RFC, Diag, Router, P4, and ICM implement custom binary protocols that receive less scrutiny than open standards. Each protocol parser is a potential memory corruption or deserialization target.
- **Dynamic code execution is a feature**: ABAP's ability to generate and execute code at runtime is used by legitimate business processes, making it impossible to simply remove the capability. The attack surface is in the *validation*, not the *mechanism*.
- **Configuration complexity creates systemic exposure**: With hundreds of authorization objects, gateway ACLs, message server ACLs, transport routes, and RFC connections, the permutation space for misconfiguration is enormous. The 10KBLAZE research estimated a high percentage of deployments were affected by permissive ACL configurations, though this figure originates from the researchers' analysis, not SAP official data.
- **Exploit weaponization timelines are compressing**: RECON (CVE-2020-6287) saw reliable exploits within 72 hours. In 2025, CVE-2025-31324 was being exploited by nation-state actors within days of disclosure, with public "turnkey" exploits released by August 2025.

### Structural Solutions

A structural improvement in SAP security requires three paradigm shifts:

1. **Zero-trust between layers**: ICM should not trust work process inputs. RFC modules should not trust caller parameters. Transport imports should be cryptographically signed end-to-end. SAP's October 2025 JVM-wide deserialization filter for Java represents a step in this direction.

2. **Elimination of implicit trust in inter-system communication**: Every RFC connection, SMDAgent communication, and transport request should require mutual authentication with non-replayable tokens — not shared secrets or default credentials.

3. **Reduction of the exposed protocol surface**: The vast majority of SAP systems do not need RFC Gateway, SAProuter, Message Server internal ports, or IGS accessible from any network beyond the immediate application cluster. Network-level segmentation is the single highest-impact defensive measure, yet external exposure scans consistently find significant numbers of Internet-exposed SAP services, demonstrating how rarely proper segmentation is implemented.

---

## References

- Onapsis Research Labs — SAP vulnerability research, CVE-2025-31324 / CVE-2025-42999 threat intelligence, ICMAD / RECON scanner tools
- SEC Consult — RFC vulnerability research whitepaper ("From RFC to RCE"), SAP kernel authentication bypass advisory
- SecurityBridge — CVE-2025-42957 discovery and wild exploitation confirmation, transport system vulnerability research
- Forescout — Chinese APT campaign threat analysis targeting SAP NetWeaver
- EclecticIQ — China-nexus actor SAP exploitation intelligence (UNC5221, UNC5174, CL-STA-0048)
- Palo Alto Unit 42 — CVE-2025-31324 threat brief and post-exploitation analysis
- ReliaQuest — Initial CVE-2025-31324 discovery and disclosure
- CISA — SAP business application exploitation advisories (2016, 2019, 2025)
- Martin Doyhenard (DEF CON 30) — Advanced Inter-Process Desynchronization in SAP's HTTP Server
- Alexander Polyakov (Black Hat 2011) — A Crushing Blow at the Heart of SAP J2EE Engine
- gelim (OPCDE 2019) — SAP Message Server research
- Tenable, Arctic Wolf, ZeroPath — Technical CVE analyses and exploitation details
- OWASP pySAP project — Open source SAP protocol library
- SecureAuthCorp — SAP Wireshark Dissection plug-in
- Airbus SecLab — PowerSAP assessment tool
- Pathlock — RFC callback attack defense and S_RFC authorization guidance
- Layer Seven Security — SAP penetration testing methodology and critical security note analysis

---

*This document was created for defensive security research and vulnerability understanding purposes.*
