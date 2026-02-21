---
name: gap-analyzer
description: "Analyze external research sources (URLs, papers, conference nominations, blog posts) against the-map taxonomy documents to find missing or underrepresented content. Produces a structured gap report with exact insertion points. Triggered when the user asks to 'find missing content', 'check for gaps', 'compare against source', 'what's not covered from X', or 'sync with latest research'. The skill performs multi-keyword duplicate verification to prevent false positives and false negatives."
---

# Gap Analyzer

Systematically compare external security research sources against the-map's existing taxonomy documents. Identify what's missing, what's partially covered, and what's fully covered — with exact file paths and section numbers for each finding.

## Core Principle

> **Triple-Check Before Declaring a Gap.**
>
> A concept may appear under a different name, in a different file, or framed from a different angle than expected. Every "NOT FOUND" verdict must survive three independent verification attempts: keyword search, semantic search (synonyms/related terms), and structural search (checking the section where it *should* logically live). Only after all three fail is a gap confirmed.

---

## Workflow Overview

```
1. SOURCE INTAKE     → Fetch and parse the external source into discrete items
2. DOCUMENT INVENTORY → Build a map of all taxonomy files and their coverage areas
3. DEEP COMPARISON   → For each item, search multiple files with multiple keywords
4. TRIPLE-CHECK      → Re-verify all "NOT FOUND" items with expanded search
5. GAP REPORT        → Produce structured report with insertion recommendations
6. DELIVERY          → Present to user for review before any edits
```

---

## Phase 1: Source Intake

### Input Types

The user may provide:
- **URL**: Conference nomination pages, blog posts, research paper lists, changelog
- **Text**: Pasted list of techniques, CVE list, paper titles
- **File**: Local document with research findings

### Extraction Goal

Parse the source into a **discrete item list**. Each item must have:

```
Item {
  id:          sequential number
  title:       research title or technique name
  author:      researcher/org (if available)
  description: 1-2 sentence summary of the core technique
  keywords:    [3-8 search terms derived from the description]
}
```

### Keyword Derivation Rules

For each item, derive keywords at three levels:

```
Level 1 — Exact terms:    specific names, CVE IDs, tool names, researcher names
Level 2 — Technical terms: the underlying mechanism (e.g., "race condition", "cache batcher")
Level 3 — Category terms:  the vulnerability class (e.g., "cache poisoning", "SSRF", "XSS")
```

**Example:**
```
Item: "Eclipse on Next.js: Conditioned exploitation of an intended race-condition"

Level 1: "Eclipse on Next.js", "zhero-web-sec", "response-cache batcher"
Level 2: "race condition", "transient pageProps", "cache batcher", "ISR revalidation"
Level 3: "Next.js", "cache poisoning", "cross-user data"
```

---

## Phase 2: Document Inventory

### Build the Coverage Map

Before comparing, build a mental map of which taxonomy files cover which topics.

#### File Discovery

```
Search pattern: the-map/**/*.md (excluding skills/, artifact-examples/, outputs/)
```

#### Coverage Map Structure

For each file, note:
```
File {
  path:        relative path from the-map root
  category:    directory name (01-injection, 02-auth, etc.)
  topic:       primary vulnerability class
  sections:    list of §N section headers
  key_terms:   terms that indicate this file's coverage area
}
```

#### Standard File-Topic Mapping

Use the directory structure as primary guide:

```
01-injection/      → SQLi, NoSQL, XSS, SSTI, XXE, command injection, etc.
02-auth/           → JWT, OAuth, SAML, CSRF, cookies, CORS, IDOR, etc.
03-http-protocol/  → smuggling, headers, HPP, WebSocket, gRPC, DNS
04-server-side/    → SSRF, path traversal, file upload, deserialization, etc.
05-client-side/    → XS-Leak, DOM clobbering, clickjacking, open redirect, etc.
06-encoding-parser/ → URL confusion, Unicode, type confusion, ZIP archives
07-application-logic/ → business logic, race conditions, timing, state machines
08-infrastructure/ → dependency confusion, cache poisoning, WAF bypass, CI/CD
09-frameworks-and-languages/ → Spring, ASP.NET, PHP, Rails, JS frameworks, etc.
10-recon-methodology/ → recon, fingerprinting, fuzzing, CTF
11-researchers/    → researcher profiles
12-product-security/ → SAP, AEM, Salesforce, SharePoint, WordPress, Nginx, Jetty
13-misc/           → AI/LLM security, DoS
```

---

## Phase 3: Deep Comparison

This is the critical phase. For each item from Phase 1, perform a **multi-file, multi-keyword search**.

### Comparison Algorithm

For each item:

```
1. IDENTIFY TARGET FILES
   - Primary file:   the file most likely to contain this topic
   - Secondary files: 2-3 related files that might cover it tangentially

2. SEARCH PRIMARY FILE
   - Search all Level 1 keywords (exact terms)
   - Search all Level 2 keywords (technical terms)
   - If any match: READ the matching section to assess depth

3. SEARCH SECONDARY FILES
   - Search Level 2 and Level 3 keywords
   - Check for the concept under different naming

4. ASSESS COVERAGE DEPTH
   - COVERED IN DEPTH:  dedicated subsection or table row with mechanism + condition
   - MENTIONED BRIEFLY:  appears in a list or passing reference, no detailed mechanism
   - PARTIALLY COVERED:  the general concept exists but the specific technique/angle is missing
   - NOT FOUND:          no match across all searched files and keywords
```

### Search Execution Rules

**CRITICAL: Use Grep tool, not Bash grep.** Search across the entire `the-map/` directory.

```
For each keyword:
  1. Grep with the exact term (case-insensitive)
  2. If no match, try shorter/variant forms
  3. If still no match, try the mechanism description words
```

**Parallel search strategy:** When checking multiple items, batch related searches together. For example, search one file for multiple keywords in a single read rather than reading the file N times.

### Coverage Assessment Criteria

```
COVERED IN DEPTH — ALL of these are true:
  ✓ Dedicated table row OR subsection
  ✓ Mechanism is described (HOW it works)
  ✓ Condition or key requirement is stated
  ✓ Would be recognizable to someone who read the source research

MENTIONED BRIEFLY — ANY of these:
  ○ Appears in a list without mechanism detail
  ○ Referenced in passing within another technique's description
  ○ Named but not explained

PARTIALLY COVERED — BOTH of these:
  ○ The general vulnerability CLASS is well-covered
  ○ But the SPECIFIC technique, angle, or research contribution is missing
  Example: "SSTI blind detection exists, but error-reflection exfiltration specifically is absent"

NOT FOUND — ALL search attempts failed:
  ✗ No exact term matches
  ✗ No mechanism-level matches
  ✗ Not found in the section where it logically should exist
```

---

## Phase 4: Triple-Check

**Every item initially classified as "NOT FOUND" or "MENTIONED BRIEFLY" must pass triple-check.**

### Check 1: Synonym Search

For each NOT FOUND item, generate 3-5 alternative phrasings:

```
Original: "credentialless iframe"
Synonyms: "COEP credentialless", "crossOriginIsolated", "anonymous iframe",
          "iframe without credentials"
```

Search all synonyms across the-map.

### Check 2: Section-Level Read

Read the FULL section where the item logically belongs. Not just keyword search — actually read the content to check if the concept is described differently.

```
Example: Item is about "HTTP/2 CONNECT for port scanning"
Read: http-request-smuggling.md §4 (H2C tunneling section) in full
Verify: Is port scanning via CONNECT described even without those exact keywords?
```

### Check 3: Cross-File Check

Check if the concept might live in an unexpected file:

```
Example: "Safari TCC prompt clickjacking"
Primary check:  ui-redressing.md (expected location)
Cross-check 1:  browser-extension-security.md (permissions topic)
Cross-check 2:  desktop-hybrid-app-security.md (native permission prompts)
```

### After Triple-Check

Update the assessment. If still NOT FOUND after all three checks, it's a confirmed gap.

---

## Phase 5: Gap Report

### Report Structure

Produce the report in this exact format:

```markdown
# Gap Analysis Report

**Source:** [source title/URL]
**Date:** [analysis date]
**Total items analyzed:** N
**Taxonomy files checked:** N

---

## Summary

| Status | Count |
|--------|-------|
| Covered in depth | N |
| Partially covered (enhancement needed) | N |
| Not covered (new content needed) | N |

---

## Fully Covered Items (No Action Needed)

| # | Item | Coverage Location |
|---|------|-------------------|
| N | [title] | [file.md] §X-Y |

---

## Partially Covered Items (Enhancement Needed)

| # | Item | Current State | Missing Element | Recommended Location |
|---|------|--------------|-----------------|---------------------|
| N | [title] | [what exists] | [what's missing] | [file.md] §X-Y — [table row / new subsection / paragraph] |

### Detailed Enhancement Descriptions

#### #N: [Item Title]

**Current coverage:** [exact quote or paraphrase of existing content]
**Gap:** [what the research adds that isn't there]
**Recommended edit:** [specific description — "add table row to §X-Y" or "add paragraph after §X-Y"]
**Content draft:** (optional, if straightforward)

---

## Not Covered Items (New Content Needed)

| # | Item | Description | Recommended File | Recommended Section | Edit Type |
|---|------|-------------|-----------------|--------------------|-----------|
| N | [title] | [1-line summary] | [file.md] | §X-Y | [new row / new subsection / new §] |

### Detailed Insertion Descriptions

#### #N: [Item Title]

**Research summary:** [2-3 sentences on what this technique is]
**Why it's missing:** [it's a new class / too niche / framework not covered / etc.]
**Recommended location:** [file.md] §X-Y — [rationale for this placement]
**Edit type:** [new table row in existing table / new subsection / new top-level section]
**CVE table entry needed:** [yes/no — if yes, draft the row]
**Keywords for future search:** [terms to find this item if searching later]
```

### Report Quality Rules

1. **Every item must appear exactly once** in one of the three categories
2. **Partially covered items must quote or reference** the existing content that's present
3. **Not covered items must include the rationale** for their recommended placement
4. **File paths must be relative** from the-map root (e.g., `04-server-side/ssrf.md`)
5. **Section references must use §-notation** matching the actual document structure

---

## Phase 6: Delivery

### Present, Don't Execute

**IMPORTANT:** The gap report is a RECOMMENDATION. Do NOT make edits automatically. Present the report and let the user choose which items to implement.

After presenting:
- User says "반영해줘" / "apply all" → proceed with all edits
- User selects specific items → apply only those
- User says "N, M, K 먼저" → apply in the specified order

### When Implementing Edits

Follow these rules strictly:

```
1. READ the target file section BEFORE editing (verify current state)
2. Match the existing table format EXACTLY (column count, separator style, bold patterns)
3. Add new rows at the LOGICAL position:
   - In tables: after the most related existing row
   - In sections: at the end, or in chronological order if dated
4. If adding a new §section, number it as the NEXT sequential number
5. Update the CVE/bounty table if a CVE is referenced
6. Update the Attack Scenario Mapping table if adding a new top-level §section
7. NEVER modify existing content — only ADD
```

---

## Appendix A: Common False Negative Patterns

These patterns frequently cause items to be incorrectly classified as "NOT FOUND":

| Pattern | Example | Solution |
|---------|---------|----------|
| **Different naming** | Research calls it "CSPT"; taxonomy calls it "client-side path manipulation" | Search for the mechanism, not just the name |
| **Split across files** | OAuth + SSRF technique split between oauth.md and ssrf.md | Check both files |
| **Buried in table row** | Technique is one cell in a large table, not a section header | Read full tables, not just headers |
| **Covered as sub-technique** | "Disk cache nonce reuse" inside a general "CSP bypass" row | Read the full text of related rows |
| **Different framing** | Research frames as "attack"; taxonomy frames as "bypass" | Search both attack and defense terms |
| **Framework-specific** | Go XML parser issue might be in type-confusion.md not a Go-specific file | Check both the general and framework-specific files |

## Appendix B: Common False Positive Patterns

These patterns cause items to be incorrectly classified as "COVERED":

| Pattern | Example | Solution |
|---------|---------|----------|
| **Category match, technique miss** | "SSRF via redirects" exists, but the specific redirect-LOOP oracle is absent | Verify the EXACT technique, not just the category |
| **Name match, mechanism miss** | "Blind SSTI" label exists, but only OOB-based, not error-reflection-based | Read the mechanism description, not just the title |
| **Old version only** | "AngularJS sandbox escape" covers 1.x constructor chain, not toString gadget | Verify the specific variant described in the research |
| **Generic mention** | "Docker security" is mentioned but not the specific container escape CVE | Check if the SPECIFIC finding is present, not just the topic |

## Appendix C: Search Query Templates

### For Exact Term Search
```
Grep pattern: "{exact_term}"
Path: the-map/ (recursive)
Mode: case-insensitive, files_with_matches first, then content for hits
```

### For Mechanism Search
```
Grep pattern: "{mechanism_keyword_1}.*{mechanism_keyword_2}"
  OR search each keyword separately and check if they co-occur in same file/section
```

### For Section-Level Verification
```
Read the target file at the § section offset
Scan for conceptual matches, not just keyword matches
```

---

*This skill was designed to eliminate false negatives (declaring something missing when it exists) and false positives (declaring something covered when only the category matches). The triple-check protocol is the key safeguard.*
