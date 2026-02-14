# Root-Cause Taxonomy — Visual Maps

---

## 1. RC Overview: 9 Root Causes & Technique Distribution

```mermaid
block-beta
  columns 3

  block:rc1:1
    columns 1
    RC1["RC1: Injection\n(13 classes)"]
    rc1t["SQLi · NoSQLi · CMDi\nXSS · SSTI · EL · XXE\nLDAP · GraphQL · JNDI\nCRLF · Email · Proto.Poll."]
  end

  block:rc2:1
    columns 1
    RC2["RC2: Parser Differential\n(12 classes)"]
    rc2t["HTTP Smuggling · URL\nUnicode · HPP · Proxy\nCookie · SAML · ZIP\nMIME · Cache · WAF · Censor"]
  end

  block:rc3:1
    columns 1
    RC3["RC3: Auth Failure\n(9 classes)"]
    rc3t["JWT · SAML · OAuth\nSSO · Reset · MFA\nSession · Credential · PreATO"]
  end

  block:rc4:1
    columns 1
    RC4["RC4: Access Control\n(5 classes)"]
    rc4t["BOLA/IDOR · BFLA\nBOPLA/Mass Assign\nCORS · Cross-Tenant"]
  end

  block:rc5:1
    columns 1
    RC5["RC5: State Violation\n(6 classes)"]
    rc5t["State Machine · Race\nCSRF · Price Logic\nFinancial · Lifecycle"]
  end

  block:rc6:1
    columns 1
    RC6["RC6: Deserialization\n(8 classes)"]
    rc6t["Java · Python · PHP\n.NET · YAML · React\nML Model · Gadget Eng."]
  end

  block:rc7:1
    columns 1
    RC7["RC7: Resource Ref\n(6 classes)"]
    rc7t["SSRF · Open Redirect\nPath Traversal · RMI\nJDBC · Webhook"]
  end

  block:rc8:1
    columns 1
    RC8["RC8: Trust Boundary\n(8 classes)"]
    rc8t["Microservice · Deputy\nDNS · Supply Chain\nCookie Scope · PostMsg\nWebSocket · JAAS"]
  end

  block:rc9:1
    columns 1
    RC9["RC9: Info Leakage\n(8 classes)"]
    rc9t["Timing · Fingerprint\nXS-Leaks · API Expose\nError · Cache · Pixel\nBrowser FP"]
  end

  style RC1 fill:#e74c3c,color:#fff
  style RC2 fill:#e67e22,color:#fff
  style RC3 fill:#f1c40f,color:#000
  style RC4 fill:#2ecc71,color:#fff
  style RC5 fill:#1abc9c,color:#fff
  style RC6 fill:#3498db,color:#fff
  style RC7 fill:#9b59b6,color:#fff
  style RC8 fill:#34495e,color:#fff
  style RC9 fill:#95a5a6,color:#fff
```

---

## 2. Cross-RC Amplification Graph

> Root causes are not independent. One RC enables or amplifies another. This graph reveals the structural reason behind real-world attack chaining.

```mermaid
graph LR
  RC9["<b>RC9</b><br/>Info Leakage"]
  RC2["<b>RC2</b><br/>Parser Diff"]
  RC1["<b>RC1</b><br/>Injection"]
  RC7["<b>RC7</b><br/>Resource Ref"]
  RC8["<b>RC8</b><br/>Trust Boundary"]
  RC3["<b>RC3</b><br/>Auth Failure"]
  RC4["<b>RC4</b><br/>Access Control"]
  RC5["<b>RC5</b><br/>State Violation"]
  RC6["<b>RC6</b><br/>Deserialization"]
  CC["<b>CC</b><br/>Control Evasion"]

  RC9 -- "fingerprint → target selection" --> RC1
  RC9 -- "schema exposure → find IDORs" --> RC4
  RC9 -- "timing oracle → extract secrets" --> RC3

  RC2 -- "WAF bypass via parser diff" --> RC1
  RC2 -- "path confusion → ACL bypass" --> RC4
  RC2 -- "smuggling → cross-user" --> RC8
  RC2 -- "cache key diff → poison" --> RC9

  RC1 -- "XXE → SSRF" --> RC7
  RC1 -- "format-crossing → nested deser" --> RC6
  RC1 -- "XSS → cookie steal" --> RC3
  RC1 -- "CRLF → cache poison" --> RC2

  RC7 -- "SSRF → internal service" --> RC8
  RC7 -- "SSRF → cloud metadata" --> RC3
  RC7 -- "open redirect → token theft" --> RC3
  RC7 -- "JNDI → deser" --> RC6

  RC8 -- "service trust → escalation" --> RC4
  RC8 -- "DNS rebinding → SSRF" --> RC7
  RC8 -- "supply chain → gadgets" --> RC6

  RC5 -- "CSRF → email change" --> RC3
  RC5 -- "TOCTOU → bypass authz check" --> RC4

  RC3 -- "session hijack → state abuse" --> RC5
  RC3 -- "token forge → privilege" --> RC4

  CC -. "amplifies" .-> RC1
  CC -. "amplifies" .-> RC2
  CC -. "amplifies" .-> RC6
  CC -. "amplifies" .-> RC7

  style RC1 fill:#e74c3c,color:#fff
  style RC2 fill:#e67e22,color:#fff
  style RC3 fill:#f1c40f,color:#000
  style RC4 fill:#2ecc71,color:#fff
  style RC5 fill:#1abc9c,color:#fff
  style RC6 fill:#3498db,color:#fff
  style RC7 fill:#9b59b6,color:#fff
  style RC8 fill:#34495e,color:#fff
  style RC9 fill:#95a5a6,color:#fff
  style CC fill:#fff,color:#333,stroke:#333,stroke-dasharray: 5 5
```

**Reading this graph**:
- **Solid arrows** = one RC enables or chains into another
- **Dashed arrows** = CC (Security Control Evasion) amplifies the target RC
- **Most connected nodes** = RC1 (Injection), RC7 (Resource Ref), RC3 (Auth) — primary chain pivots
- **Key insight**: RC2 (Parser Diff) and RC7 (Resource Ref) are the strongest "enablers" — hub nodes that activate other RCs. Blocking these two weakens the entire chain graph.

---

## 3. Impact Convergence: Multiple Paths to Same Impact

> Multiple root causes converge on the same impact. Defending by impact is futile — each RC path must be blocked independently at its root cause.

```mermaid
graph LR
  subgraph "Root Causes"
    RC1["RC1: Injection"]
    RC2["RC2: Parser Diff"]
    RC3["RC3: Auth"]
    RC4["RC4: Access Ctrl"]
    RC5["RC5: State"]
    RC6["RC6: Deser"]
    RC7["RC7: Resource"]
    RC8["RC8: Trust"]
    RC9["RC9: Info Leak"]
  end

  subgraph "Impact"
    RCE["Remote Code Execution"]
    ATO["Account Takeover"]
    EXFIL["Data Exfiltration"]
    PRIVESC["Privilege Escalation"]
    FRAUD["Financial Fraud"]
    LATERAL["Lateral Movement"]
    DOS["Denial of Service"]
  end

  RC1 --> |"SQLi→cmd, SSTI, EL"| RCE
  RC6 --> |"gadget chain"| RCE
  RC7 --> |"JNDI, RMI"| RCE
  RC4 --> |"Spring4Shell"| RCE

  RC3 --> |"token forge, MFA bypass"| ATO
  RC1 --> |"XSS→cookie"| ATO
  RC5 --> |"CSRF→email change"| ATO
  RC8 --> |"SSO linking"| ATO

  RC1 --> |"SQLi, XXE"| EXFIL
  RC4 --> |"IDOR mass enum"| EXFIL
  RC9 --> |"timing, XS-Leaks"| EXFIL
  RC2 --> |"cache deception"| EXFIL
  RC7 --> |"SSRF→metadata"| EXFIL
  RC8 --> |"cross-tenant"| EXFIL

  RC4 --> |"BFLA, mass assign"| PRIVESC
  RC3 --> |"JWT claim, OAuth scope"| PRIVESC
  RC2 --> |"path confusion→ACL"| PRIVESC
  RC8 --> |"confused deputy"| PRIVESC

  RC5 --> |"price, coupon, race"| FRAUD

  RC8 --> |"service trust"| LATERAL
  RC7 --> |"SSRF→internal"| LATERAL
  RC2 --> |"smuggling→hijack"| LATERAL

  RC1 --> |"XXE billion laughs, ReDoS"| DOS
  RC5 --> |"cart bombing"| DOS
  RC6 --> |"zip bomb"| DOS
  RC2 --> |"smuggling→desync"| DOS

  style RCE fill:#c0392b,color:#fff
  style ATO fill:#e74c3c,color:#fff
  style EXFIL fill:#e67e22,color:#fff
  style PRIVESC fill:#f39c12,color:#fff
  style FRAUD fill:#d35400,color:#fff
  style LATERAL fill:#8e44ad,color:#fff
  style DOS fill:#7f8c8d,color:#fff
```

**Key insights**:
- **Data Exfiltration** is reachable from the most RCs (6 paths) — the widest attack surface
- **RCE** is reachable from 4 independent RCs — blocking one path leaves the others intact
- **Financial Fraud** is reachable only from RC5 — securing state integrity alone eliminates this impact class
- **DoS** is reachable from 4 RCs but is generally the lowest-priority impact for most organizations

---

## 4. Common Real-World Attack Chains

> Real-world attacks are not single-RC events — they are RC chains. These are the most frequently observed multi-RC combinations.

```mermaid
graph TD
  subgraph "Chain 1: Classic Web App Compromise"
    A1["RC9: Fingerprinting\n(identify framework)"] --> A2["RC1: Injection\n(SQLi/SSTI found)"]
    A2 --> A3["CC: WAF Bypass\n(encoding mutation)"]
    A3 --> A4["RC1→RCE\n(command execution)"]
  end

  subgraph "Chain 2: API-First ATO"
    B1["RC9: API Schema Exposure\n(Swagger/GraphQL introspection)"] --> B2["RC4: IDOR\n(user data enumeration)"]
    B2 --> B3["RC3: Auth Bypass\n(JWT claim manipulation)"]
    B3 --> B4["Account Takeover"]
  end

  subgraph "Chain 3: Cloud Infrastructure Pivot"
    C1["RC1: XXE/SSRF\n(initial entry)"] --> C2["RC7: SSRF\n(cloud metadata 169.254.169.254)"]
    C2 --> C3["RC3: IAM Credential Theft"]
    C3 --> C4["RC8: Cross-Service Lateral\n(assume-role)"]
  end

  subgraph "Chain 4: Supply Chain → RCE"
    D1["RC8: Dependency Confusion\n(malicious package)"] --> D2["RC6: Deserialization\n(gadget chain activated)"]
    D2 --> D3["Remote Code Execution"]
  end

  subgraph "Chain 5: Parser Diff → Cross-User"
    E1["RC2: HTTP Smuggling\n(CL.TE desync)"] --> E2["RC3: Session Hijack\n(response queue poison)"]
    E2 --> E3["RC4: Privilege Escalation\n(admin session captured)"]
  end

  subgraph "Chain 6: Logic → Financial"
    F1["RC5: Race Condition\n(TOCTOU)"] --> F2["RC5: Double-Spend\n(parallel withdraw)"]
    F2 --> F3["Financial Fraud"]
  end

  style A4 fill:#c0392b,color:#fff
  style B4 fill:#e74c3c,color:#fff
  style C4 fill:#8e44ad,color:#fff
  style D3 fill:#c0392b,color:#fff
  style E3 fill:#f39c12,color:#fff
  style F3 fill:#d35400,color:#fff
```

---

## 5. Defense Priority: Attack Surface × Impact Severity

> Which RCs to defend first? Prioritized by Attack Surface (number of connected RCs and entry points) × Impact Severity (worst-case achievable outcome).

```mermaid
quadrantChart
    title Defense Priority Matrix
    x-axis "Low Attack Surface" --> "High Attack Surface"
    y-axis "Low Impact Severity" --> "High Impact Severity"

    RC1 Injection: [0.85, 0.90]
    RC2 Parser Diff: [0.75, 0.55]
    RC3 Auth Failure: [0.70, 0.95]
    RC4 Access Control: [0.60, 0.75]
    RC5 State Violation: [0.40, 0.65]
    RC6 Deserialization: [0.35, 0.95]
    RC7 Resource Ref: [0.80, 0.80]
    RC8 Trust Boundary: [0.65, 0.70]
    RC9 Info Leakage: [0.50, 0.30]
```

**Reading the quadrant**:
- **Top-Right (defend first)**: RC1 (Injection), RC3 (Auth), RC7 (Resource Ref) — high attack surface + high impact
- **Top-Left (high impact, narrow surface)**: RC6 (Deserialization) — instant RCE when found, but entry points are limited
- **Bottom-Right (wide surface, lower standalone impact)**: RC2 (Parser Diff) — less direct impact, but the strongest enabler for other RCs
- **Bottom-Left (lower priority)**: RC9 (Info Leakage) — low standalone impact, but often the first step in a chain

---

## 6. Root Cause → Security Principle → Defense Control

> Practical blue team mapping: each RC maps to a violated security principle, which maps to concrete defense controls.

```mermaid
graph LR
  subgraph "Root Cause"
    RC1["RC1: Injection"]
    RC2["RC2: Parser Diff"]
    RC3["RC3: Auth"]
    RC4["RC4: Access Ctrl"]
    RC5["RC5: State"]
    RC6["RC6: Deser"]
    RC7["RC7: Resource Ref"]
    RC8["RC8: Trust"]
    RC9["RC9: Info Leak"]
  end

  subgraph "Security Principle"
    P1["Data/Control\nSeparation"]
    P2["Consistent\nInterpretation"]
    P3["Identity\nVerification"]
    P4["Authorization\nEnforcement"]
    P5["State\nIntegrity"]
    P6["Data/Code\nSeparation"]
    P7["Reference\nValidation"]
    P8["Trust\nVerification"]
    P9["Information\nMinimization"]
  end

  subgraph "Primary Control"
    C1["Parameterized Queries\nContext-Aware Encoding\nAllowlist Validation"]
    C2["Single Authoritative Parser\nReject Ambiguous Input\nNormalize at Entry"]
    C3["Algorithm Allowlist\nSession Lifecycle Mgmt\nHardware MFA"]
    C4["Data-Layer AuthZ\nDeny by Default\nUUIDv4 Identifiers"]
    C5["Server-Side State Machine\nDB-Level Locks\nIdempotency Keys"]
    C6["Never Deser Untrusted\nClass Allowlist\nSafe Formats (JSON)"]
    C7["URL/Path Allowlist\nDNS Resolution Check\nNetwork Isolation"]
    C8["mTLS Between Services\nOrigin Validation\nDependency Pinning"]
    C9["Generic Errors\nConstant-Time Comparison\nDisable Debug/Introspection"]
  end

  RC1 --> P1 --> C1
  RC2 --> P2 --> C2
  RC3 --> P3 --> C3
  RC4 --> P4 --> C4
  RC5 --> P5 --> C5
  RC6 --> P6 --> C6
  RC7 --> P7 --> C7
  RC8 --> P8 --> C8
  RC9 --> P9 --> C9

  style P1 fill:#e74c3c,color:#fff
  style P2 fill:#e67e22,color:#fff
  style P3 fill:#f1c40f,color:#000
  style P4 fill:#2ecc71,color:#fff
  style P5 fill:#1abc9c,color:#fff
  style P6 fill:#3498db,color:#fff
  style P7 fill:#9b59b6,color:#fff
  style P8 fill:#34495e,color:#fff
  style P9 fill:#95a5a6,color:#fff
```

---

## Summary: What These Visuals Reveal

| Diagram | Key Insight |
|---|---|
| **#2 Amplification Graph** | RC2 (Parser Diff) and RC7 (Resource Ref) are "hub" nodes — they enable the most other RCs. Blocking these two weakens the entire attack chain graph. |
| **#3 Impact Convergence** | Data Exfiltration is reachable from 6 RCs. Defending by impact class is futile — each RC path must be eliminated at its root cause. |
| **#4 Attack Chains** | Real-world attacks chain 2-4 RCs. Breaking any single link in the chain stops the entire attack. |
| **#5 Defense Priority** | RC1 (Injection) + RC3 (Auth) + RC7 (Resource) sit in the top-right quadrant. These three are the highest-priority defense targets. |
| **#6 RC → Principle → Control** | Implementing 9 security principles eliminates 340+ technique variants at the root cause level. |
