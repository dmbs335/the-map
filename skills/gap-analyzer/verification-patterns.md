# Verification Patterns — Lessons from Real Gap Analyses

This document captures real false-positive and false-negative patterns encountered during gap analysis. Use it as a checklist during the Triple-Check phase.

---

## Real False Negatives (Item existed but was initially missed)

### Pattern: Covered under a generalized name

| Research Item | Expected Search Term | Actual Location |
|--------------|---------------------|-----------------|
| "Opossum Attack" | "opossum", "cross-protocol" | `http-request-smuggling.md` §6-1 "TLS-Layer Desync" — described as "TLS Upgrade Desync" |
| "Funky chunks" | "funky chunks" | `http-request-smuggling.md` §5-2 "Two-byte terminator overread" — no mention of the research name |
| "The Fragile Lock" | "fragile lock" | `saml.md` §3-1 "Void Canonicalization" — the mechanism, not the paper title |
| "SOAPwn" | "SOAPwn" | `asp-dot-net.md` §9-1 — found as "WSDL-Based RCE" not "SOAPwn" |

**Lesson:** Always search for the MECHANISM, not just the research NAME.

### Pattern: Split across two files

| Research Item | Expected File | Also Found In |
|--------------|--------------|---------------|
| "CSWSH via GraphQL" | `websocket.md` | Also in `graphql.md` (batching + OTP brute-force) |
| "OAuth + SSRF chain" | `oauth.md` | Also in `ssrf.md` §7-2 (OAuth/OpenID callbacks) |
| "Prototype pollution → XSS" | `prototype-pollution.md` | Also in `xss.md` §6-2 |

**Lesson:** Always check at least 2 files per item — the primary topic file AND the secondary technique file.

### Pattern: Buried in a table row

| Research Item | How it was found |
|--------------|-----------------|
| "MySQL full-text search boolean operator" | Single table row in `sql-injection.md` §3-1, no subsection header |
| "PDO null byte misparsing" | Single table row in `sql-injection.md` §8-3 |
| "Stopping redirects for OAuth" | Single table row in `oauth.md` §2-2 |

**Lesson:** Keyword-only search is insufficient. Must READ full table contents of the target section.

---

## Real False Positives (Item seemed covered but wasn't)

### Pattern: Category match but technique miss

| Research Item | What seemed to cover it | What was actually missing |
|--------------|------------------------|--------------------------|
| "Blind SSTI error reflection" | `ssti.md` §7-2 "DNS/time-based blind detection" existed | The SPECIFIC technique of reflecting data in error messages was absent |
| "CSP nonce disk cache reuse" | `browser-security-model.md` §2-4 had CSP bypass rows | The SPECIFIC mechanism of disk cache → nonce recovery was absent |
| "SSRF redirect loop oracle" | `ssrf.md` §7-1 "redirect chains" existed | The SPECIFIC technique of using loop iteration status codes as an oracle was absent |

**Lesson:** Verify the EXACT technique variant, not just the category. "Redirect chain SSRF" ≠ "Redirect loop status-code oracle SSRF".

### Pattern: Old variant only

| Research Item | What existed | What was missing |
|--------------|-------------|-----------------|
| "Expression sandbox escape via toString" | AngularJS `constructor.constructor` chain in §9-1 | The toString/valueOf implicit coercion path was different |
| "AEAD tag truncation → subkey recovery" | GCM tag truncation → forgery in crypto file | The subkey H recovery via truncation (not just forgery) was absent |

**Lesson:** Multiple VARIANTS of the same technique can exist. Finding one variant doesn't mean the specific new variant is covered.

### Pattern: Concept exists in a different context

| Research Item | Where it seemed to exist | Why it wasn't actually covered |
|--------------|-------------------------|-------------------------------|
| "credentialless iframe" | COEP section in `browser-security-model.md` | Mentioned only for COEP/CORP bypass — NOT for self-XSS escalation |
| "Go float64 JSON" | `type-confusion-and-coercion.md` §10-4 | JSON precision covered — but XML parser and duplicate key handling were absent |

**Lesson:** Same KEYWORD in a DIFFERENT CONTEXT does not constitute coverage.

---

## Verification Checklist Template

For each "NOT FOUND" verdict, fill this checklist before confirming:

```
Item: [title]
Primary file checked: [file.md] — sections read: [§X, §Y]
Secondary files checked: [file2.md, file3.md]

☐ Searched exact research name/title
☐ Searched CVE number (if any)
☐ Searched researcher name
☐ Searched mechanism keywords (2-3 terms)
☐ Searched synonym/alternative names
☐ Read full table of the section where it SHOULD logically exist
☐ Checked for the concept under a different framing

Verdict: [CONFIRMED NOT FOUND / ACTUALLY EXISTS at ...]
```

For each "COVERED" verdict, fill this checklist:

```
Item: [title]
Found in: [file.md] §X-Y
Match type: [exact name / mechanism match / category match]

☐ Verified the SPECIFIC technique (not just the category)
☐ Verified the SPECIFIC variant (not just an older version)
☐ Verified the mechanism description matches the research contribution
☐ If category-only match: checked if the specific angle is also present

Verdict: [CONFIRMED COVERED / ACTUALLY PARTIAL — missing: ...]
```
