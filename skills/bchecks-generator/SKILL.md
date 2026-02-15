---
name: bchecks-generator
description: "Generate Burp Suite bchecks (Bambdas + BChecks) from the-map taxonomy documents. This skill creates Bambdas for custom Burp Suite automation and BChecks for scanner checks based on mutation taxonomy. Triggered when the user requests 'create bchecks', 'generate Bambdas', 'make Burp scanner bchecks', or wants to automate Burp Suite workflows from taxonomy. Bchecks use a domain-specific language for lightweight scanner extensions."
---

# Bchecks Generator

Generate **Burp Suite bchecks and Bambdas** from the-map vulnerability taxonomy documents. Bchecks are lightweight scanner checks using Burp's DSL, while Bambdas are Java snippets for request/response automation.

## Core Principle

> **Lightweight Detection from Taxonomy**
>
> Each mutation variant becomes a bcheck scanner rule. Unlike full extensions, bchecks use Burp's built-in DSL for faster development and deployment. Bambdas complement bchecks with custom request filtering and transformation logic.

---

## Workflow Overview

```
1. TARGET SELECTION    → Identify the-map document
2. TAXONOMY ANALYSIS   → Extract mutation variants
3. BCHECK DESIGN       → Map to bcheck language constructs
4. CODE GENERATION     → Generate .bcheck and .bambda files
5. VALIDATION          → Test bcheck syntax
6. DELIVERY            → Package with README
```

---

## BCheck Language Fundamentals

### BCheck Structure

```
metadata:
    language: v2-beta
    name: "[Vulnerability] - [Subtype]"
    description: "[Mechanism from taxonomy]"
    author: "the-map"
    tags: "[vuln]", "[category]"

define:
    issueDetail = `[Issue detail template]`

given request then
    # Insertion point selection
    if {base.request.url.path} matches "/api" then
        # Payload injection
        send request called check:
            replacing path: "/api" + "{payload}"

        if {check.response.status_code} is "200" and
           {check.response.body} contains "vulnerable" then
            report issue:
                severity: high
                confidence: certain
                detail: `{issueDetail}`
                remediation: "[Remediation advice]"
        end if
    end if
```

### Key Components

1. **Metadata**: Template information and tags
2. **Variables**: Payload definitions and constants
3. **Request Logic**: Insertion points and payload injection
4. **Matchers**: Response validation rules
5. **Reporting**: Issue creation with severity

---

## Phase 1-2: Target Selection & Analysis

Same as Burp Extension Generator - read taxonomy, identify subtypes.

---

## Phase 3: BCheck Design

### Mapping Taxonomy to BChecks

```
Taxonomy Subtype → BCheck Structure
─────────────────────────────────────
§N-M Subtype → Single .bcheck file
  ├── Metadata from taxonomy reference
  ├── Payload from "Example" column
  ├── Matcher from "Detection" logic
  └── Severity from Axis 3 (Attack Scenario)
```

### BCheck Categories

#### 1. Simple Payload Injection

```
metadata:
    language: v2-beta
    name: "XSS - Event Handler Auto-Fire"
    description: "Detects XSS via <img onerror> injection"
    author: "the-map"
    tags: "xss", "injection"

define:
    payloads = ["<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<input autofocus onfocus=alert(1)>"]

given request then
    for payload in {payloads} then
        send request called check:
            replacing all query parameters: {payload}

        if {check.response.status_code} is "200" and
           {check.response.body} contains {payload} and
           {check.response.headers} contains "text/html" then
            report issue:
                severity: high
                confidence: firm
                detail: `Reflected XSS detected with payload: {payload}`
        end if
    end for
```

#### 2. Header-Based Detection

```
metadata:
    language: v2-beta
    name: "CORS - Reflected Origin"
    description: "Detects CORS misconfiguration reflecting arbitrary origins"
    author: "the-map"
    tags: "cors", "misconfiguration"

given request then
    send request called check:
        modifying headers:
            replace header: "Origin" value: "https://evil.com"

    if {check.response.headers} matches "Access-Control-Allow-Origin: https://evil.com" and
       {check.response.headers} contains "Access-Control-Allow-Credentials: true" then
        report issue:
            severity: high
            confidence: certain
            detail: `CORS allows arbitrary origins with credentials`
    end if
```

#### 3. Differential Detection

```
metadata:
    language: v2-beta
    name: "Path Traversal - Encoding Bypass"
    description: "Tests path traversal with URL encoding variations"
    author: "the-map"
    tags: "traversal", "encoding"

define:
    traversals = ["../../../etc/passwd",
                  "..%2f..%2f..%2fetc%2fpasswd",
                  "..%252f..%252f..%252fetc%252fpasswd"]

given request then
    for traversal in {traversals} then
        send request called check:
            replacing path: {base.request.url.path} + traversal

        if {check.response.body} matches "root:[x*]:0:0:" then
            report issue:
                severity: critical
                confidence: certain
                detail: `Path traversal successful: {traversal}`
        end if
    end for
```

---

## Bambdas (Request/Response Processing)

### Bambda Structure

Bambdas are Java lambda expressions for Burp automation:

```java
// Filter requests matching pattern
return requestResponse.request().hasHeader("Authorization") &&
       requestResponse.request().url().contains("/api/");
```

### Common Bambda Patterns

#### 1. Request Filtering (for targeted testing)

```java
// bambdas/filter-api-endpoints.bambda
// Description: Filter API endpoints for testing

return requestResponse.request().hasParameter("id") ||
       requestResponse.request().hasParameter("user") ||
       requestResponse.request().url().path().contains("/api/");
```

#### 2. Response Highlighting (for anomaly detection)

```java
// bambdas/highlight-error-messages.bambda
// Description: Highlight responses with error messages

var body = requestResponse.response().bodyToString();
return body.contains("error") ||
       body.contains("exception") ||
       body.contains("stack trace") ||
       requestResponse.response().statusCode() >= 500;
```

#### 3. Parameter Extraction

```java
// bambdas/extract-jwt-tokens.bambda
// Description: Extract JWT tokens from responses

var body = requestResponse.response().bodyToString();
var jwtPattern = "eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*";
return body.matches(".*" + jwtPattern + ".*");
```

---

## Phase 4: Code Generation

### File Organization

```
bchecks-the-map-[vulnerability]/
├── bchecks/
│   ├── [vuln]-[category]-[subtype].bcheck
│   └── ...
├── bambdas/
│   ├── filter-[context].bambda
│   ├── highlight-[pattern].bambda
│   └── extract-[data].bambda
├── payloads/
│   └── [category]/
│       └── [subtype].txt
└── README.md
```

### Generation Rules

#### Rule 1: Taxonomy Metadata

```
Every bcheck must include:
  - name: [Vulnerability] - [Subtype from taxonomy]
  - description: [Mechanism from taxonomy]
  - tags: Taxonomy category + vulnerability type
  - Inline comment with taxonomy reference
```

#### Rule 2: Payload Organization

```
Short payload lists (< 5): Inline in define block
Long payload lists: External file + read from payloads/
```

#### Rule 3: Severity Mapping

```
Axis 3 Attack Scenario → BCheck severity
─────────────────────────────────────────
RCE / Auth bypass → high
Session hijack → high
Information disclosure → medium
CSRF / Open redirect → low
```

#### Rule 4: Confidence Levels

```
certain: Exact pattern match (e.g., root:x:0:0:)
firm: Strong indicator (e.g., error message with payload)
tentative: Weak indicator (e.g., timing difference)
```

### BCheck Template

```
metadata:
    language: v2-beta
    name: "[Vulnerability] - [Subtype Name]"
    description: |
        [Mechanism from taxonomy]

        Taxonomy Reference: the-map/[path]/[file].md §[N]-[M]
    author: "the-map"
    tags: "[vuln]", "[category]", "[framework]"

define:
    # Payloads from taxonomy "Example" column
    payloads = ["[payload1]", "[payload2]", "[payload3]"]

    # Detection patterns
    successPattern = "[pattern from taxonomy]"

    issueDetail = `
        <p><b>Taxonomy Reference:</b> the-map/[path] §[N]-[M]</p>
        <p><b>Mutation Target:</b> [Target]</p>
        <p><b>Mechanism:</b> [Mechanism from taxonomy]</p>
        <p><b>Payload Used:</b> {payload}</p>
        <p><b>Detection:</b> {detection_evidence}</p>
    `

given request then
    # Filter applicable requests (from "Key Condition")
    if [condition from taxonomy] then

        for payload in {payloads} then
            send request called check:
                [injection method based on subtype]

            # Matcher logic (from detection method)
            if [matcher conditions] then
                report issue:
                    severity: [from Axis 3]
                    confidence: [based on detection strength]
                    detail: `{issueDetail}`
                    remediation: |
                        [Remediation advice from taxonomy or best practices]
            end if
        end for

    end if
```

---

## Phase 5: Validation

### BCheck Syntax Validation

Load into Burp Suite and check for syntax errors:

```
1. Burp Suite → Extensions → BChecks
2. Load .bcheck file
3. Check for syntax errors in Burp's validator
4. Test against known vulnerable endpoint
```

### Bambda Testing

```
1. Burp Suite → Logger/Proxy → Right-click → Filter by bambda
2. Paste bambda code
3. Verify correct filtering behavior
```

---

## Phase 6: Delivery

### README Template

```markdown
# BChecks - [Vulnerability] (The Map)

Burp Suite BChecks and Bambdas for [vulnerability] detection based on
the-map taxonomy.

## Contents

- **BChecks**: [N] scanner checks for mutation variants
- **Bambdas**: [M] request/response processing snippets
- **Payloads**: Organized payload files by category

## Installation

### BChecks

1. Burp Suite → Extensions → BChecks
2. Click "Load BCheck from file"
3. Select .bcheck files from `bchecks/` directory

### Bambdas

1. Burp Suite → Logger/Proxy → Right-click → Filter by bambda
2. Copy bambda code from `bambdas/` directory
3. Paste into Burp's bambda editor

## BChecks Coverage

| Taxonomy Section | BCheck File | Severity | Payloads |
|-----------------|-------------|----------|----------|
| §1-1 | [file].bcheck | high | [N] |
| §1-2 | [file].bcheck | medium | [M] |
...

## Bambdas

### Request Filters

- **filter-[context].bambda**: [Description]
- **filter-[type].bambda**: [Description]

### Response Highlighters

- **highlight-[pattern].bambda**: [Description]
- **highlight-[error].bambda**: [Description]

### Data Extractors

- **extract-[data].bambda**: [Description]

## Usage

### Running BChecks

1. Load bchecks into Burp Suite
2. Enable in Scanner settings
3. Scan target: Dashboard → New scan → Configure scope
4. BChecks run automatically during scan

### Using Bambdas

**Filter API requests:**
```java
// Copy from bambdas/filter-api-endpoints.bambda
return requestResponse.request().url().contains("/api/");
```

**Highlight vulnerable responses:**
```java
// Copy from bambdas/highlight-xss-reflection.bambda
var body = requestResponse.response().bodyToString();
return body.contains("<script>") && body.contains("alert");
```

## Taxonomy Mapping

Complete mapping in TAXONOMY_MAPPING.md

## License

MIT License - see LICENSE file
```

---

## Advanced Features

### Multi-Request BChecks

```
given request then
    # Step 1: Get CSRF token
    send request called getToken:
        replacing path: "/get-token"

    # Extract token
    define tokenPattern = `csrf_token" value="([^"]+)"`

    if {getToken.response.body} matches {tokenPattern} then
        # Step 2: Use token in attack
        send request called attack:
            modifying headers:
                add header: "X-CSRF-Token" value: {extracted_token}
            replacing body: "param={payload}"

        if {attack.response} matches "success" then
            report issue
        end if
    end if
```

### Conditional Logic

```
given request then
    # Only test POST requests with JSON body
    if {base.request.method} is "POST" and
       {base.request.headers} contains "application/json" then

        # Test JSON injection
        for payload in {jsonPayloads} then
            send request called check:
                replacing body: {payload}

            if {check.response.status_code} is "500" then
                report issue
            end if
        end for
    end if
```

---

## Quality Checklist

- [ ] **All bchecks have taxonomy references**
- [ ] **Payloads match taxonomy examples**
- [ ] **Severity matches Axis 3**
- [ ] **BChecks validate in Burp Suite**
- [ ] **Bambdas compile without errors**
- [ ] **README documents all files**
- [ ] **TAXONOMY_MAPPING.md complete**

---

## Delivery Message

```markdown
# BChecks Generated

Generated [N] BChecks and [M] Bambdas for [Vulnerability] detection.

## Summary

- **BChecks**: [N] scanner checks
- **Bambdas**: [M] processing snippets
- **Taxonomy Coverage**: [X] subtypes
- **Severity**: [A] high, [B] medium, [C] low

## Quick Start

1. Load bchecks: Burp → Extensions → BChecks → Load from file
2. Run scan: Dashboard → New scan
3. Use bambdas: Logger → Filter by bambda

All checks backed by the-map taxonomy mutation variants.
```

---

## Notes

- **Language**: v2-beta (latest BCheck language)
- **Burp Version**: Requires Burp Suite Professional 2023.9+
- **Limitations**: BChecks are lighter than full extensions but less flexible
- **Use Case**: Quick deployment of taxonomy-based checks
- **Complementary**: Use with Burp Extension Generator for comprehensive coverage
