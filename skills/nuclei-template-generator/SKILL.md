---
name: nuclei-template-generator
description: "Generate Nuclei vulnerability detection templates from the-map taxonomy documents. This skill converts mutation variants from the-map knowledge base into production-ready Nuclei YAML templates with matchers, extractors, and workflows. Triggered when the user requests 'create Nuclei template', 'generate Nuclei YAML', 'make scanner template', or references specific vulnerabilities for automated testing. Supports both simple templates and complex workflows with chaining."
---

# Nuclei Template Generator

Generate **production-ready Nuclei templates** from the-map vulnerability taxonomy documents. Templates include HTTP requests, matchers, extractors, and multi-step workflows based on taxonomy mutation variants.

## Core Principle

> **From Taxonomy to Detection Templates**
>
> Every mutation variant becomes a Nuclei template test case. The three-axis structure (Mutation Target, Discrepancy Type, Attack Scenario) maps to Nuclei primitives: what to send (payloads), what to match (detection), and how to chain (workflows).

---

## Workflow Overview

```
1. TARGET SELECTION    → Identify which the-map document to convert
2. TAXONOMY ANALYSIS   → Parse mutation axes and subtypes
3. TEMPLATE DESIGN     → Map subtypes to Nuclei request/match patterns
4. YAML GENERATION     → Generate Nuclei template YAML files
5. VALIDATION          → Lint templates and test structure
6. DELIVERY            → Package templates with README and workflows
```

---

## Phase 1: Target Selection

### Input Patterns

The user may request:
- "Create Nuclei templates for XSS detection from the-map"
- "Generate Nuclei YAML for SSRF testing"
- "Make scanner templates for JWT vulnerabilities"
- "Convert the HTTP Request Smuggling taxonomy to Nuclei"

### Target Identification

```
User: "Nuclei templates for JWT" → the-map/02-auth/jwt/jwt.md
User: "SSRF scanner templates" → the-map/04-server-side/ssrf/ssrf.md
User: "HTTP smuggling detection" → the-map/03-http-protocol/.../http-request-smuggling.md
```

### Scope Confirmation

If taxonomy is very large (50+ subtypes):
```
Options:
1. Generate comprehensive template pack (all variants)
2. Focus on high/critical severity variants
3. Split by category (one template per §section)
4. Create workflow templates (multi-step detection)
```

---

## Phase 2: Taxonomy Analysis

### Axis Extraction

Parse taxonomy to extract Nuclei template structure:

```markdown
## Axis 1: Mutation Targets → HTTP Request Variations
§1. [Category 1] → Template ID: [vuln]-category1-*
§2. [Category 2] → Template ID: [vuln]-category2-*

## Axis 2: Discrepancy Types → Matcher Strategies
- Encoding differential → Multiple request encodings + response match
- Parser differential → Baseline + mutated request diff
- WAF evasion → Raw request with bypass techniques
- CSP bypass → Header analysis + script load detection

## Axis 3: Attack Scenarios → Severity Classification
- RCE → critical
- Auth bypass → high
- Information disclosure → medium
- Misc → low
```

### Subtype to Template Mapping

For each subtype:

```
Subtype: [Name]
Mechanism: [How it works] → Nuclei request
Example Payload: [Concrete test] → payload variable
Key Condition: [When to test] → matcher condition
Detection Method: [Response pattern] → matcher type

Template Structure:
  id: [vuln]-[category]-[subtype-slug]
  info:
    name: from subtype name
    severity: from Axis 3
    description: from mechanism
    reference: taxonomy URL
  requests:
    - raw/http method based on attack type
  matchers:
    - type based on detection method
```

---

## Phase 3: Template Design

### Nuclei Template Anatomy

```yaml
id: [vulnerability]-[category]-[variant]

info:
  name: "[Vulnerability] - [Subtype Name]"
  author: the-map
  severity: [critical|high|medium|low|info]
  description: |
    [Mechanism from taxonomy]
  reference:
    - [the-map taxonomy URL]
  classification:
    cvss-metrics: [if available]
    cvss-score: [if available]
    cwe-id: [if applicable]
  metadata:
    max-request: [number of requests]
    taxonomy-section: "§[N]-[M]"
  tags: [vulnerability],[category],[framework]

http:
  - method: [GET|POST|PUT|etc]
    path:
      - "{{BaseURL}}/[endpoint]"

    # OR for raw requests (HTTP smuggling, etc):
    raw:
      - |
        [raw HTTP request with payload]

    # Payload variables
    payloads:
      param: [payload list]

    # Attack mode
    attack: [pitchfork|clusterbomb|batteringram]

    # Matchers
    matchers-condition: and
    matchers:
      - type: [word|regex|status|dsl]
        part: [body|header|all]
        words:
          - "[detection string]"
        condition: and

    # Extractors (optional)
    extractors:
      - type: [regex|kval|xpath]
        part: body
        regex:
          - "[extraction pattern]"
```

### Template Categories

#### 1. Simple Detection Templates

For straightforward payload injection + response match:

```yaml
id: xss-reflected-img-onerror

info:
  name: "XSS - Event Handler Element Injection (Auto-firing)"
  author: the-map
  severity: high
  description: |
    Detects reflected XSS via <img> tag with onerror handler.
    Taxonomy: XSS §1-2 Event Handler Element Injection
  reference:
    - https://github.com/.../the-map/01-injection/xss/xss.md#1-2
  metadata:
    taxonomy-section: "§1-2"
  tags: xss,injection,reflected

http:
  - method: GET
    path:
      - "{{BaseURL}}{{path}}?{{param}}={{payload}}"

    payloads:
      param: helpers/params.txt
      payload:
        - '<img src=x onerror=alert(1)>'
        - '<img src=x onerror=alert(document.domain)>'
        - '<svg onload=alert(1)>'
        - '<input autofocus onfocus=alert(1)>'

    attack: clusterbomb

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '<img src=x onerror=alert('
          - '<svg onload=alert('
          - '<input autofocus onfocus=alert('
        condition: or

      - type: word
        part: header
        words:
          - "text/html"

      - type: status
        status:
          - 200
```

#### 2. Multi-Step Workflow Templates

For complex attacks requiring multiple requests:

```yaml
id: jwt-algorithm-confusion-workflow

info:
  name: "JWT - Algorithm Confusion Attack"
  author: the-map
  severity: critical
  description: |
    Tests JWT algorithm confusion vulnerability (RS256→HS256).
    Taxonomy: JWT §2-1 Algorithm Confusion
  reference:
    - https://github.com/.../the-map/02-auth/jwt/jwt.md#2-1
  metadata:
    taxonomy-section: "§2-1"
  tags: jwt,authentication,algorithm-confusion

workflows:
  - template: jwt-algorithm-confusion-workflow.yaml

# Separate workflow file
---
id: jwt-algorithm-confusion-workflow

info:
  name: JWT Algorithm Confusion Multi-Step
  author: the-map

workflows:
  - tags: jwt-fetch-pubkey
    subtemplates:
      - template: jwt-fetch-rsa-public-key.yaml
        subtemplates:
          - template: jwt-algorithm-confusion-attack.yaml
```

#### 3. Differential Templates

For parser differential / smuggling attacks:

```yaml
id: http-smuggling-clte-basic

info:
  name: "HTTP Request Smuggling - CL.TE Desync"
  author: the-map
  severity: critical
  description: |
    Detects CL.TE HTTP desync vulnerability.
    Front-End uses Content-Length, Back-End uses Transfer-Encoding.
    Taxonomy: HTTP Request Smuggling §1-1
  reference:
    - https://github.com/.../the-map/03-http-protocol/.../http-request-smuggling.md#1-1
  metadata:
    taxonomy-section: "§1-1"
  tags: http,smuggling,desync,clte

http:
  - raw:
      - |
        POST /search HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 49
        Transfer-Encoding: chunked

        0

        GET /admin HTTP/1.1
        Host: {{Hostname}}


    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "admin")'
        condition: and

      - type: word
        part: body
        words:
          - "admin panel"
          - "administrator"
        condition: or

    # Confirm with timing
    matchers:
      - type: dsl
        dsl:
          - 'duration >= 10'  # Timeout indicates desync
```

#### 4. Header-Based Detection Templates

For vulnerabilities detected via response headers:

```yaml
id: cors-misconfiguration-reflected-origin

info:
  name: "CORS Misconfiguration - Reflected Origin"
  author: the-map
  severity: high
  description: |
    Detects CORS misconfiguration reflecting arbitrary origins.
    Taxonomy: CORS Misconfiguration §1-1
  metadata:
    taxonomy-section: "§1-1"
  tags: cors,misconfiguration,origin-reflection

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      Origin: "https://evil.com"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Credentials: true"
        condition: and
```

#### 5. Blind/OOB Detection Templates

For blind vulnerabilities using interactsh:

```yaml
id: ssrf-dns-oob-detection

info:
  name: "SSRF - DNS Out-of-Band Detection"
  author: the-map
  severity: high
  description: |
    Detects SSRF via DNS OOB callback using interactsh.
    Taxonomy: SSRF §1-1
  metadata:
    taxonomy-section: "§1-1"
  tags: ssrf,oob,dns,interactsh

http:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url=http://{{interactsh-url}}"
      - "{{BaseURL}}/proxy?target={{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"
```

---

## Phase 4: YAML Generation

### Generation Rules

#### Rule 1: Taxonomy Metadata

Every template MUST include:

```yaml
info:
  reference:
    - [direct link to taxonomy section]
  metadata:
    taxonomy-section: "§[N]-[M]"
  description: |
    [Mechanism from taxonomy]
    Taxonomy: [Vulnerability] §[N]-[M] [Subtype Name]
```

#### Rule 2: Naming Conventions

```
Template ID format:
  [vulnerability-slug]-[category-slug]-[subtype-slug]

Examples:
  xss-html-element-script-injection
  jwt-algorithm-confusion-rs256-hs256
  ssrf-url-scheme-file-protocol
  http-smuggling-clte-basic
```

#### Rule 3: Payload Organization

```
Payloads from taxonomy:
1. Base payload from "Example" column
2. Encoding variations from Axis 2
3. Context-specific mutations

Storage:
  payloads/[vulnerability]/[category]/[subtype].txt
```

#### Rule 4: Severity Mapping

Map Axis 3 (Attack Scenario) to Nuclei severity:

```yaml
Attack Scenario → Severity
RCE → critical
Auth bypass → critical
Privilege escalation → critical
Session hijack → high
Information disclosure → medium
ACL bypass → medium
CSRF → medium
Open redirect → low
Information leak (minimal) → info
```

#### Rule 5: Matcher Precision

```yaml
# AVOID: Too broad (false positives)
matchers:
  - type: word
    words:
      - "error"

# PREFER: Specific pattern from taxonomy
matchers-condition: and
matchers:
  - type: regex
    regex:
      - '<img[^>]+src=x[^>]+onerror=[^>]*alert\('

  - type: word
    part: header
    words:
      - "text/html"

  - type: status
    status:
      - 200
```

### Template Organization Structure

```
nuclei-the-map-templates/
├── http/
│   ├── vulnerabilities/
│   │   ├── xss/
│   │   │   ├── xss-html-element-script.yaml
│   │   │   ├── xss-attribute-breakout.yaml
│   │   │   ├── xss-javascript-context.yaml
│   │   │   └── ...
│   │   ├── jwt/
│   │   │   ├── jwt-algorithm-confusion.yaml
│   │   │   ├── jwt-none-algorithm.yaml
│   │   │   └── ...
│   │   ├── ssrf/
│   │   ├── smuggling/
│   │   └── ...
│   └── workflows/
│       ├── jwt-full-test-workflow.yaml
│       ├── auth-bypass-chain.yaml
│       └── ...
├── payloads/
│   ├── xss/
│   │   ├── html-element.txt
│   │   ├── attribute-breakout.txt
│   │   └── ...
│   ├── jwt/
│   ├── ssrf/
│   └── ...
├── helpers/
│   ├── params.txt          # Common parameter names
│   ├── paths.txt           # Common paths
│   └── headers.txt         # Common headers
└── README.md
```

### Workflow Templates

For complex multi-step attacks:

```yaml
# workflows/jwt-algorithm-confusion-full.yaml
id: jwt-algorithm-confusion-full

info:
  name: "JWT Algorithm Confusion - Full Attack Chain"
  author: the-map
  severity: critical
  description: Complete JWT algorithm confusion test
  reference:
    - https://github.com/.../jwt.md

workflows:
  - template: http/vulnerabilities/jwt/jwt-detect-usage.yaml
    subtemplates:
      - template: http/vulnerabilities/jwt/jwt-fetch-pubkey.yaml
        subtemplates:
          - template: http/vulnerabilities/jwt/jwt-algorithm-confusion-attack.yaml

      - template: http/vulnerabilities/jwt/jwt-none-algorithm.yaml

      - template: http/vulnerabilities/jwt/jwt-weak-secret.yaml
        matchers:
          - name: weak-secret-found
            subtemplates:
              - template: http/vulnerabilities/jwt/jwt-forge-token.yaml
```

---

## Phase 5: Validation

### Template Linting

Run Nuclei template validation:

```bash
# Validate syntax
nuclei -t [template-file] -validate

# Dry run
nuclei -t [template-file] -u https://example.com -debug
```

### Quality Checks

- [ ] **Valid YAML syntax**
- [ ] **Required fields present** (id, info.name, info.severity)
- [ ] **Taxonomy reference in info.reference**
- [ ] **Taxonomy section in info.metadata**
- [ ] **Matchers are specific** (not overly broad)
- [ ] **Payloads match taxonomy examples**
- [ ] **Severity matches attack scenario** (Axis 3)
- [ ] **Tags include vulnerability type**
- [ ] **No hardcoded credentials** (use variables)
- [ ] **Description includes mechanism**

### False Positive Testing

For each template, include false positive checks:

```yaml
# Example: Ensure matcher is specific enough
matchers-condition: and
matchers:
  - type: word
    part: body
    words:
      - "specific-pattern-from-taxonomy"
    condition: and

  # Negative matcher to reduce FP
  - type: word
    part: body
    words:
      - "false-positive-indicator"
    negative: true
```

---

## Phase 6: Delivery

### Package Structure

```
nuclei-the-map-[vulnerability]/
├── templates/
│   ├── http/
│   │   └── vulnerabilities/
│   │       └── [vuln]/
│   │           ├── *.yaml (individual templates)
│   │           └── workflows/
│   └── payloads/
│       └── [vuln]/
│           └── *.txt
├── README.md
├── TAXONOMY_MAPPING.md
└── examples/
    └── vulnerable-targets.md
```

### Output Location

Save to: `c:\Users\dmbs3\Downloads\the-map\outputs\nuclei-the-map-[vulnerability]\`

### README Template

```markdown
# Nuclei Templates - [Vulnerability] (The Map)

Nuclei vulnerability detection templates for [vulnerability] based on
[the-map](https://github.com/...) mutation taxonomy.

## Overview

- **Taxonomy Source**: [the-map/path/file.md]
- **Templates**: [X] templates covering [Y] mutation variants
- **Severity Breakdown**: [N] critical, [M] high, [P] medium
- **Detection Types**: Direct, Differential, Blind/OOB, Multi-step
- **Workflows**: [Z] complex attack chains

## Installation

```bash
# Clone this repository
git clone https://github.com/.../nuclei-the-map-[vuln]

# Or add to Nuclei templates directory
cp -r templates/* ~/nuclei-templates/
```

## Usage

### Scan Single Target

```bash
nuclei -u https://target.com -t templates/http/vulnerabilities/[vuln]/
```

### Scan with Specific Category

```bash
# Test only category §1 variants
nuclei -u https://target.com -t templates/http/vulnerabilities/[vuln]/[category]-*.yaml
```

### Run Full Workflow

```bash
nuclei -u https://target.com -w templates/workflows/[vuln]-full-test.yaml
```

### Scan URL List

```bash
nuclei -l urls.txt -t templates/http/vulnerabilities/[vuln]/
```

## Template Coverage

### §1. [Category 1 Name]

| Template ID | Subtype | Severity | Type |
|------------|---------|----------|------|
| [vuln]-[cat]-[sub] | [Subtype Name] | [Severity] | [Direct/Diff/Blind] |
| ... | ... | ... | ... |

### §2. [Category 2 Name]

[Continue for all categories]

## Taxonomy Mapping

Each template directly implements taxonomy sections:

```
Taxonomy §N-M → Template ID
────────────────────────────
§1-1 [Subtype] → [vuln]-[category]-[variant].yaml
§1-2 [Subtype] → [vuln]-[category]-[variant].yaml
...
```

See [TAXONOMY_MAPPING.md](TAXONOMY_MAPPING.md) for complete mapping.

## Payloads

Payloads are organized by taxonomy category:

```
payloads/
├── [category1]/
│   ├── [subtype1].txt    # Base payloads from taxonomy
│   ├── [subtype1]-encoded.txt   # Encoding variations (Axis 2)
│   └── ...
└── ...
```

### Custom Payloads

To add custom payloads:

1. Edit `payloads/[category]/[subtype].txt`
2. Add one payload per line
3. Templates automatically use updated payloads

## Configuration

### Variables

Templates support customization via Nuclei variables:

```bash
# Custom headers
nuclei -u https://target.com -t templates/ -H "Authorization: Bearer TOKEN"

# Custom rate limiting
nuclei -u https://target.com -t templates/ -rl 10

# Proxy
nuclei -u https://target.com -t templates/ -proxy http://127.0.0.1:8080
```

### Severity Filtering

```bash
# Only critical/high
nuclei -u https://target.com -t templates/ -s critical,high

# Exclude info
nuclei -u https://target.com -t templates/ -es info
```

## Workflows

Complex attack chains combining multiple templates:

### [Workflow Name]

**File**: `workflows/[workflow].yaml`

**Steps**:
1. [Step 1 description] → [template-id]
2. [Step 2 description] → [template-id]
3. [Step 3 description] → [template-id]

**Usage**:
```bash
nuclei -u https://target.com -w workflows/[workflow].yaml
```

## Examples

### Vulnerable Test Applications

See [examples/vulnerable-targets.md](examples/vulnerable-targets.md) for:
- Intentionally vulnerable applications
- Expected detections
- Payload effectiveness

### Real-World CVEs Detected

| CVE | Product | Template(s) | Taxonomy Reference |
|-----|---------|-------------|-------------------|
| [CVE-XXXX-YYYY] | [Product] | [template-id] | §[N]-[M] |
| ... | ... | ... | ... |

## Development

### Adding New Templates

1. Identify taxonomy subtype in [the-map/path/file.md]
2. Create template: `templates/http/vulnerabilities/[vuln]/[id].yaml`
3. Add payloads: `payloads/[category]/[subtype].txt`
4. Update TAXONOMY_MAPPING.md
5. Validate: `nuclei -t [template] -validate`

### Testing Templates

```bash
# Syntax validation
nuclei -t templates/ -validate

# Dry run
nuclei -t templates/[template].yaml -u https://example.com -debug

# Against vulnerable target
nuclei -t templates/ -u http://vulnerable-app:8080
```

## Contributing

Contributions welcome! Please:
1. Reference taxonomy section in template metadata
2. Include description with mechanism
3. Add payloads to appropriate category
4. Validate templates before PR
5. Update TAXONOMY_MAPPING.md

## Credits

Based on [the-map](https://github.com/...) vulnerability taxonomy.

Taxonomy research: [author/contributors]

## License

MIT License - see LICENSE file
```

### TAXONOMY_MAPPING.md Template

```markdown
# Taxonomy to Template Mapping

Complete mapping of taxonomy sections to Nuclei templates.

## Taxonomy Source

File: [the-map/path/file.md]

Last Updated: [date]

## Mapping Table

| Taxonomy Section | Subtype Name | Template ID | Severity | File Path |
|-----------------|--------------|-------------|----------|-----------|
| §1-1 | [Subtype] | [template-id] | [severity] | templates/http/.../[file].yaml |
| §1-2 | [Subtype] | [template-id] | [severity] | templates/http/.../[file].yaml |
| ... | ... | ... | ... | ... |

## Coverage Statistics

- **Total Taxonomy Subtypes**: [N]
- **Templates Generated**: [M]
- **Coverage**: [M/N * 100]%
- **Workflows**: [P]

## Not Yet Implemented

Templates pending for:

- [ ] §[X]-[Y]: [Subtype Name] — [Reason]
- [ ] §[X]-[Z]: [Subtype Name] — [Reason]

## Template Categories

### Direct Detection ([N] templates)

Simple payload injection + response match:
- [list of template IDs]

### Differential Detection ([M] templates)

Requires baseline comparison:
- [list of template IDs]

### Blind/OOB Detection ([P] templates)

Uses interactsh or timing:
- [list of template IDs]

### Multi-Step Workflows ([Q] templates)

Complex attack chains:
- [list of workflow IDs]
```

---

## Advanced Features

### Interactsh Integration

For blind vulnerabilities (SSRF, XXE, etc.):

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url=http://{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
          - "smtp"
        condition: or
```

### Dynamic Payload Generation

Use Nuclei helper functions:

```yaml
http:
  - raw:
      - |
        GET {{path}}?param={{base64(payload)}} HTTP/1.1
        Host: {{Hostname}}

    payloads:
      path: helpers/paths.txt
      payload: payloads/xss/basic.txt

    attack: clusterbomb
```

### Conditional Matching

Multi-condition matchers:

```yaml
matchers-condition: and
matchers:
  - type: dsl
    dsl:
      - 'status_code == 200'
      - 'contains(body, "success")'
      - 'len(body) > 100'
    condition: and

  - type: word
    part: header
    words:
      - "X-Vulnerable: true"
```

### Request Chaining

Multi-request templates:

```yaml
http:
  # Request 1: Get CSRF token
  - method: GET
    path:
      - "{{BaseURL}}/login"
    extractors:
      - type: regex
        name: csrf
        regex:
          - 'csrf_token" value="([^"]+)"'
        internal: true

  # Request 2: Use token in attack
  - method: POST
    path:
      - "{{BaseURL}}/update"
    body: "csrf={{csrf}}&param={{payload}}"

    matchers:
      - type: word
        words:
          - "success"
```

---

## Quality Checklist

Before delivery, verify:

- [ ] **All taxonomy subtypes have corresponding templates**
- [ ] **Each template has taxonomy reference in metadata**
- [ ] **Payloads match taxonomy examples**
- [ ] **Matchers are specific (no overly broad patterns)**
- [ ] **Severity matches attack scenario (Axis 3)**
- [ ] **Templates validate**: `nuclei -t * -validate`
- [ ] **No syntax errors**
- [ ] **README documents all templates**
- [ ] **TAXONOMY_MAPPING.md is complete**
- [ ] **Workflows tested for complex chains**
- [ ] **Payloads organized by category**

---

## Delivery Message Template

```markdown
# Nuclei Templates Generated

I've created a complete Nuclei template pack for [Vulnerability] detection
based on the-map taxonomy.

## Summary

- **Taxonomy Source**: [the-map/path/file.md]
- **Templates Generated**: [X] templates
- **Subtypes Covered**: [Y] mutation variants
- **Severity Distribution**: [N] critical, [M] high, [P] medium
- **Workflows**: [Z] multi-step attack chains
- **Payload Files**: [A] organized by category

## Quick Start

```bash
cd nuclei-the-map-[vuln]
nuclei -u https://target.com -t templates/
```

## Template Organization

| Category | Templates | Coverage |
|----------|-----------|----------|
| §1. [Category] | [N] templates | [X]% |
| §2. [Category] | [M] templates | [Y]% |
...

## Files Generated

1. **Templates**: [X] YAML files in `templates/http/vulnerabilities/[vuln]/`
2. **Workflows**: [Z] workflow files for complex chains
3. **Payloads**: [A] payload files organized by category
4. **Documentation**: README + TAXONOMY_MAPPING
5. **Examples**: Vulnerable target list

## Testing

All templates validated with:
```bash
nuclei -t templates/ -validate
```

## Next Steps

1. Review templates in `templates/` directory
2. Customize payloads in `payloads/` if needed
3. Run against test targets: `nuclei -u TARGET -t templates/`
4. Use workflows for complex tests: `nuclei -w workflows/[workflow].yaml -u TARGET`

The templates are production-ready and follow Nuclei best practices.
All detection logic is backed by the taxonomy's mutation variants.
```

---

## Notes

- **Language**: All templates and docs in English
- **Nuclei Version**: Target latest stable Nuclei version
- **Licensing**: MIT license, attribute the-map taxonomy
- **Maintainability**: Organize by taxonomy structure for easy updates
- **Interactsh**: Use for blind/OOB vulnerabilities
- **Workflows**: Create for complex multi-step attacks
- **False Positives**: Use specific matchers, avoid broad patterns
