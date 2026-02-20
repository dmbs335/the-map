---
name: gap-merger
description: "Merge gap analysis findings into existing the-map taxonomy documents with surgical precision. Takes gap report items (from gap-analyzer or user) and produces edits that blend naturally with each target document's existing format, voice, and structure. Performs a final duplicate check before every edit. Triggered when the user asks to 'merge gaps', 'apply gap report', 'reflect findings', '반영해줘', or specifies item numbers to implement from a gap analysis. CRITICAL: Only adds content explicitly specified — never injects unrequested additions."
---

# Gap Merger

Surgically merge new research findings into existing the-map taxonomy documents. Every edit must be indistinguishable from the original document's style — as if the original author had written it.

## Core Principle

> **Read Before You Write. Check Before You Commit.**
>
> Every edit follows a strict protocol: (1) Read the target section, (2) Verify no duplicate exists *right now* (not from a prior scan — the file may have changed), (3) Match the exact format, (4) Insert at the logical position. If a duplicate IS found during the pre-edit check, SKIP the item and report it — never create redundant content.

---

## Workflow Overview

```
1. INTAKE           → Parse items to merge (from gap report or user selection)
2. PRE-EDIT CHECK   → For each item: read target file, verify no duplicate NOW
3. FORMAT ANALYSIS  → Capture the exact table/section format of the insertion point
4. CONTENT DRAFTING → Write the new content matching format precisely
5. SURGICAL EDIT    → Apply the edit at the exact insertion point
6. POST-EDIT VERIFY → Read back the edited section to confirm correctness
7. CVE/TABLE UPDATE → Update auxiliary tables if needed (CVE mapping, Attack Scenarios)
```

---

## Phase 1: Intake

### Input Types

The user may provide:
- **Gap report items by number:** "#1, #12, #13 먼저 해줘"
- **Gap report items by name:** "Next.js cache batcher, CSP nonce disk cache"
- **Full gap report:** Output from gap-analyzer skill
- **Free-form description:** "Add X to Y file"

### Parse Each Item Into

```
MergeItem {
  id:              item number or identifier
  title:           research title
  target_file:     absolute path to the taxonomy file to edit
  target_section:  §-notation of the insertion point
  edit_type:       "table_row" | "subsection" | "paragraph" | "new_section"
  content_summary: what to add (the research finding)
  cvr_entry:       whether CVE/bounty table also needs updating
}
```

### Strict Content Scope Rule

**ONLY add what the user specified.** Do not:
- Add related techniques that weren't in the gap report
- "Improve" surrounding text while you're editing
- Add comments, docstrings, or explanatory notes not in the original style
- Fix typos or formatting in existing content (unless explicitly asked)
- Add cross-references to other documents (unless the existing style does this)

---

## Phase 2: Pre-Edit Duplicate Check

**This is the most critical safety step.** The gap analysis may have been done hours or days ago. The file may have been edited since then.

### For Each Item, Before Any Edit:

```
1. READ the target file at the target section (±20 lines around §)
2. SEARCH for these terms in the CURRENT file content:
   a. The research name / technique name
   b. The CVE number (if any)
   c. 2-3 mechanism keywords unique to this technique
3. DECISION:
   - If ANY match with substantial overlap → SKIP, report as "already present"
   - If PARTIAL match (same category, different variant) → PROCEED with care
   - If NO match → PROCEED with edit
```

### Duplicate Check Search Strategy

```python
# Pseudocode for each item
keywords = [item.title, item.cve, *item.mechanism_keywords]
for keyword in keywords:
    results = grep(keyword, target_file, case_insensitive=True)
    if results:
        read_context(results, ±5 lines)
        if context_matches_item_semantically:
            SKIP("Duplicate found: {keyword} at line {N}")
            break
```

### When a Duplicate IS Found

Report to user immediately:
```
⚠️ #{id} "{title}" — SKIPPED
   이미 존재: {file}:{line_number}
   기존 내용: "{existing text snippet}"
```

---

## Phase 3: Format Analysis

Before writing any content, capture the EXACT format of the insertion point.

### Table Format Capture

Read the existing table and extract:

```
Table Format {
  column_count:     number of columns
  column_headers:   exact header text ["Subtype", "Mechanism", "Key Condition"]
  separator_style:  "|---|---|---|" or "|---------|-----------|---------------|"
  bold_pattern:     is the first column bold? ("**Name**" or "Name")
  cell_style:       how long are typical cells (1 sentence? 2-3 sentences?)
  examples_inline:  do cells contain inline code examples?
}
```

### Section Format Capture

```
Section Format {
  header_level:    ### for subsection, ## for section
  intro_paragraph: does the section have a 1-2 sentence intro before the table?
  table_follows:   is there always a table after the intro?
  cross_refs:      does the section use §-notation cross-references?
  ending:          does the section end with a blank line? horizontal rule?
}
```

### Voice Analysis

Read 3-5 nearby table rows and note:
```
Voice {
  person:          passive ("is exploited") or active ("attacker exploits")
  detail_level:    terse (10-20 words per cell) or detailed (40-80 words)
  example_style:   inline code, payload example, or just description
  condition_style: "Requires X" or "X + Y" or "When X is configured"
}
```

---

## Phase 4: Content Drafting

### Table Row Template

Match the captured format EXACTLY. Draft the row, then verify:

```
Checklist:
☐ Column count matches existing table
☐ First column uses same bold pattern
☐ Mechanism description uses same voice (passive/active) as neighbors
☐ Detail level is comparable (not 3x longer or shorter than adjacent rows)
☐ If existing rows have inline code examples, include one
☐ If existing rows cite CVEs inline, follow same pattern
☐ Key condition uses same phrasing style as neighbors
☐ Research attribution follows existing pattern:
    - Most tables: NO attribution in the table body
    - Some tables: "(CVE-XXXX-YYYY)" inline
    - Some tables: "(researcher, year)" for very recent findings
    Check 3+ existing rows to determine which pattern this table uses
```

### New Subsection Template

```markdown
### §{N}-{M}. {Descriptive Title}

{1-2 sentence intro matching the voice of adjacent subsections}

| {col1} | {col2} | {col3} |
|{sep1}|{sep2}|{sep3}|
| **{Name}** | {mechanism} | {condition} |
```

### New Top-Level Section Template

```markdown
## §{N}. {Section Title}

{1-2 sentence overview paragraph explaining what this section covers and why it matters.}

### §{N}-1. {First Subsection}

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **{Name}** | {mechanism} | {condition} |
```

### Content Length Calibration

**CRITICAL:** Match the length of adjacent entries. If existing rows have 20-30 word mechanisms, don't write a 100-word mechanism. If existing rows have 60-80 word mechanisms, don't write a 15-word mechanism.

```
To calibrate:
1. Read 3 adjacent table rows in the target table
2. Count words in each "Mechanism" cell
3. Target your new row's mechanism at the MEDIAN length
4. If you're ±30% of the median, it's acceptable
5. If you're >2x the median, shorten
6. If you're <0.5x the median, expand
```

---

## Phase 5: Surgical Edit

### Insertion Position Rules

```
For TABLE ROW additions:
  - Insert AFTER the most topically related existing row
  - If no related row, insert at the END of the table (before the blank line)
  - NEVER insert before the header/separator rows

For SUBSECTION additions:
  - Insert AFTER the last existing subsection in the parent §
  - Use the next sequential number: if §7-5 is the last, add §7-6
  - NEVER insert between two existing subsections (breaks numbering)

For NEW §SECTION additions:
  - Insert BEFORE the first non-taxonomy section (Attack Scenario Mapping, CVE table, etc.)
  - Use the next sequential number: if §11 is the last, add §12
  - Add a horizontal rule (---) before and after
```

### Edit Execution

Use the Edit tool with:
- `old_string`: The exact text around the insertion point (typically the last row + next section header)
- `new_string`: The old text with the new row/section inserted
- `replace_all: false` — always single replacement

**If the Edit fails** (string not unique or file changed):
1. Re-read the file
2. Re-verify duplicate check
3. Retry with a more unique old_string (include more surrounding context)

---

## Phase 6: Post-Edit Verification

After each edit, read the edited section to verify:

```
☐ Table renders correctly (column alignment, no broken rows)
☐ New content is at the intended position
☐ Surrounding content is unchanged
☐ No duplicate rows were created
☐ Section numbering is still sequential
```

---

## Phase 7: Auxiliary Table Updates

### CVE / Bounty Mapping Table

If the added item references a specific CVE:

```
1. Read the CVE table at the end of the target file
2. Verify the CVE is not already listed
3. Add a new row following the format:
   | §{section ref} ({technique name}) | CVE-XXXX-YYYY (Product) | {impact description} |
4. Insert in chronological order or after related entries
```

### Attack Scenario Mapping Table

If a new top-level §section was added:

```
1. Read the Attack Scenario Mapping table
2. Add a row mapping the new section to its attack scenario
3. Follow existing format exactly
```

---

## Batch Processing Rules

When merging multiple items:

### Parallelizable Edits (different files)
```
Items targeting DIFFERENT files can be edited in parallel.
Example: #1 → modern-js-frameworks.md AND #12 → browser-security-model.md
→ Can run both edits simultaneously
```

### Sequential Edits (same file)
```
Items targeting the SAME file MUST be edited sequentially.
Example: #12 → browser-security-model.md §2-4 AND #28 → browser-security-model.md §2-1
→ Edit #28 first, then re-read and edit #12 (or vice versa)
→ NEVER reference stale line numbers from a prior read after editing
```

### After All Edits

Report a summary:
```markdown
## Merge Summary

| # | Item | File | Section | Status |
|---|------|------|---------|--------|
| 1 | {title} | {file} | §X-Y | ✅ Added |
| 2 | {title} | {file} | §X-Y | ⚠️ Skipped (duplicate) |
| 3 | {title} | {file} | §X-Y | ✅ Added + CVE table updated |
```

---

## Anti-Patterns (What NOT To Do)

### 1. Scope Creep
```
❌ "While I'm editing xss.md, let me also fix this typo and add a cross-reference"
✅ Only touch what was requested. Period.
```

### 2. Format Mismatch
```
❌ Adding a 150-word mechanism cell when neighbors have 30-word cells
✅ Match the median length of adjacent rows (±30%)
```

### 3. Stale Read
```
❌ Reading the file once, then making 3 edits based on that single read
✅ Re-read after each edit to the same file
```

### 4. Attribution Inconsistency
```
❌ Adding "(Smith et al., 2025)" when no other row in the table has attributions
✅ Check how 3+ existing rows handle attribution and match that pattern
```

### 5. Phantom Content
```
❌ "I'll also add this related technique that wasn't in the gap report but seems relevant"
✅ ONLY add items explicitly requested. Suggest others separately if desired.
```

### 6. Over-Engineering New Sections
```
❌ Adding a new §12 with 4 subsections, intro paragraph, and tool matrix for a single technique
✅ If there's only one technique, a single subsection (§12-1) with one table row is sufficient
```

---

## Edge Cases

### Item Partially Exists But Needs Enhancement

When the gap analysis says "PARTIALLY COVERED — add the specific technique":

```
1. Read the existing entry that partially covers it
2. Determine if the enhancement is:
   a. A NEW TABLE ROW (add alongside the partial match)
   b. An EXTENSION of an existing row (expand the mechanism text)
   c. A NEW SUBSECTION (when the new angle is architecturally different)
3. Prefer (a) over (b) over (c) — minimize disruption
```

### Conflicting Information

If the new research contradicts existing content:

```
DO NOT modify existing content.
ADD the new finding as a separate entry.
Let the user decide whether to reconcile.
```

### Very Niche Items

If an item is extremely specific (single CVE, single product, no generalizable pattern):

```
Prefer: CVE table entry only (not a new taxonomy subtype)
Unless: The technique introduces a genuinely new STRUCTURAL pattern
```

---

*This skill exists to make edits that are invisible — the reader should never be able to tell which content was added later. Format fidelity is not optional.*
