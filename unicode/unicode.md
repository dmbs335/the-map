# Unicode Vulnerability Mutation Taxonomy

A comprehensive classification of attack techniques that exploit Unicode processing, encoding, normalization, and rendering behaviors to bypass security controls, deceive users, or achieve unauthorized access.

---

## Classification Structure

Unicode vulnerabilities arise from a fundamental tension: Unicode is a rich, complex system designed for universal text representation, but security controls — filters, validators, comparators, renderers — must make decisions based on simplified interpretations of that text. Every mutation in this taxonomy exploits a **discrepancy** between how two or more components interpret the same Unicode input.

The taxonomy is organized along three axes:

**Axis 1 — Mutation Target (Primary Structure):** The specific Unicode processing mechanism being exploited — encoding, normalization, visual rendering, character properties, invisible characters, or width/mapping transformations. This axis structures the main body of the document (§1–§8).

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the mismatch between components:

| Discrepancy Type | Description |
|-----------------|-------------|
| **Encoding Mismatch** | Two components decode the same byte sequence differently |
| **Normalization Mismatch** | Pre-normalization vs. post-normalization values differ across security boundary |
| **Visual-Semantic Gap** | What a human sees differs from what the machine processes |
| **Property Mismatch** | Character properties (case, width, length, category) change across a transformation |
| **Visibility Gap** | Characters are invisible to humans/scanners but processed by the target system |
| **Mapping Mismatch** | A character is substituted during charset conversion, producing security-relevant output |

**Axis 3 — Attack Scenario (Where Weaponized):** The architectural context in which the mutation achieves impact — WAF bypass, authentication bypass, path traversal, XSS, SQLi, phishing/spoofing, source code supply chain, LLM/AI manipulation, data exfiltration, or denial of service.

---

## §1. Encoding-Level Mutations

Mutations that exploit how Unicode byte sequences are decoded, re-encoded, or converted between character encoding schemes. These are among the oldest Unicode attacks and target the foundational layer of text processing.

### §1-1. Overlong UTF-8 Encoding

UTF-8 encodes code points in 1–4 bytes, with each code point having exactly one valid minimal encoding. An **overlong encoding** uses more bytes than necessary by padding with leading zeros. The UTF-8 specification (RFC 3629) explicitly forbids overlong sequences, but vulnerable decoders accept them.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Overlong Null Byte** | U+0000 encoded as `0xC0 0x80` instead of `0x00` bypasses null-byte checks in C-string-based filters while being decoded to a null terminator by the backend | Decoder accepts overlong sequences; filter checks raw bytes |
| **Overlong Slash** | `/` (U+002F) encoded as `0xC0 0xAF` bypasses path traversal filters checking for literal `0x2F` | Security check occurs before UTF-8 decoding |
| **Overlong Dot** | `.` (U+002E) encoded as `0xC0 0xAE` bypasses `..` directory traversal filters | Same as above |
| **Multi-Stage Overlong** | 3-byte or 4-byte overlong representations of ASCII characters (e.g., `0xE0 0x80 0xAF` for `/`) evade filters that only check 2-byte overlong patterns | Partial overlong detection in filter |

**Historical Impact:** The IIS Unicode directory traversal vulnerability (CVE-2001-0333) exploited overlong encodings of `..` and `/` to access arbitrary files. The Nimda and Code Red II worms propagated using this vector.

**Root Cause:** Decoder leniency — accepting byte sequences that violate the UTF-8 minimal encoding requirement.

### §1-2. Double/Multi-Layer Encoding

A character is encoded, then the encoded representation is encoded again. If decoding occurs multiple times (once by a security filter, again by the backend), the filter sees a benign encoded form while the backend recovers the malicious character.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double URL Encoding** | `../` → `%2E%2E%2F` → `%252E%252E%252F`; filter decodes once and sees `%2E%2E%2F` (harmless), backend decodes again to `../` | Filter and backend each perform one decoding pass |
| **Mixed Encoding Layers** | Combining URL encoding with UTF-8 encoding: `%C0%AF` (overlong UTF-8 of `/` in URL-encoded form) | Multiple decoders in pipeline, each handling different encoding layer |
| **Triple Encoding** | Three layers of encoding to bypass filters that detect double encoding | Filter specifically checks for double encoding but not triple |

### §1-3. Charset Mismatch Exploitation

Different components interpret the same byte sequence using different character encoding schemes (e.g., UTF-8 vs. GBK vs. Shift_JIS vs. Latin-1), producing different characters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Multi-Byte Escape Eating** | In GBK encoding, `0xBF27` with `addslashes()` becomes `0xBF5C27` — but `0xBF5C` is a valid GBK character, so the escape backslash (`0x5C`) is consumed, leaving a bare single quote (`0x27`) | Database connection uses GBK; escaping function uses ASCII/Latin-1 |
| **UTF-7 Injection** | Input containing `+ADw-script+AD4-` is interpreted as `<script>` by a UTF-7 decoder, bypassing filters checking UTF-8 input | Response lacks explicit charset declaration; browser falls back to UTF-7 auto-detection |
| **Shift_JIS Backslash Consumption** | Certain Shift_JIS lead bytes consume the following backslash as part of a multi-byte character, neutralizing escape sequences | Application uses Shift_JIS internally; escaping logic is byte-oriented |
| **Charset Declaration Manipulation** | Attacker injects or modifies charset declarations (BOM, HTTP header, meta tag) to force reinterpretation of the document in a different encoding | Application does not explicitly set charset or allows user-controlled charset parameters |

### §1-4. BOM (Byte Order Mark) Manipulation

The Unicode BOM (U+FEFF) can be exploited when different components handle it inconsistently — some strip it, some treat it as content, and some use it for encoding detection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **BOM-Based Encoding Switch** | Injecting a UTF-16 BOM (`0xFF 0xFE`) before content forces re-interpretation as UTF-16, completely changing how subsequent bytes are decoded | Parser uses BOM for encoding auto-detection |
| **BOM as Filter Bypass** | Prepending a BOM to a payload shifts byte offsets, breaking pattern-matching filters that expect content at specific positions | Filter does not strip or account for BOM |

---

## §2. Normalization Mutations

Unicode normalization transforms equivalent sequences into a canonical form (NFC, NFD, NFKC, NFKD). Vulnerabilities arise when normalization occurs **after** security validation but **before** consumption, or when different components use different normalization forms.

### §2-1. Compatibility Decomposition Bypass (NFKC/NFKD)

Compatibility normalization maps "fancy" variants of characters to their plain equivalents. Hundreds of Unicode code points normalize to ASCII characters that have security significance.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fullwidth Character Bypass** | Fullwidth characters (U+FF01–U+FF5E) normalize to ASCII equivalents: `＜` → `<`, `＞` → `>`, `＇` → `'`. Payloads like `＜script＞` pass filters checking for ASCII `<script>` but normalize to executable HTML | Filter checks pre-normalization input; backend normalizes before rendering |
| **Mathematical/Styled Variant Bypass** | Mathematical symbols (U+1D400–U+1D7FF) and styled letters normalize to ASCII: `𝕃` → `L`, `𝓈𝓬𝓻𝓲𝓹𝓽` → `script` | Same as above |
| **Superscript/Subscript Normalization** | `¹`, `²`, `³` (U+00B9, U+00B2, U+00B3) normalize to `1`, `2`, `3` | Numeric validation performed pre-normalization |
| **Ligature Decomposition** | Ligatures like `ﬁ` (U+FB01) decompose to `fi`, `ﬆ` (U+FB06) to `st` | Keyword filters checking for whole words miss ligature forms |
| **Circle/Parenthesized Forms** | Circled letters like `①`, `Ⓐ` decompose to `1`, `A` | Same pattern as fullwidth bypass |

**Special K Polyglot:** A well-known payload technique constructs XSS, SQLi, or command injection entirely from Unicode characters that are individually benign but normalize into an exploit string under NFKC/NFKD.

### §2-2. Canonical Equivalence Exploitation (NFC/NFD)

NFC and NFD handle combining characters differently. NFD decomposes characters into base + combining marks; NFC composes them. Security issues arise when comparison or filtering uses one form while storage or execution uses another.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Composed vs. Decomposed Comparison Failure** | `é` can be NFC (U+00E9, single code point) or NFD (U+0065 + U+0301, two code points). A filter checking for `é` in NFC form misses the NFD representation | String comparison without prior normalization |
| **Length Discrepancy** | NFD decomposition increases the number of code points (and potentially bytes). A length check on NFC input may pass, but the NFD-expanded form exceeds buffer boundaries | Length validation before normalization; buffer allocation after |
| **Hash/Signature Mismatch** | Two canonically equivalent strings produce different hashes if not normalized first, enabling duplicate key injection or signature bypass | Hash computed on raw bytes without normalization |

### §2-3. Case Mapping Collisions

Unicode case mapping (uppercasing/lowercasing) can map distinct characters to the same output, or map characters across script boundaries in unexpected ways.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Eszett Collision** | `ß` (U+00DF) uppercases to `SS` in many locales. Registering a username/email with `ß` may collide with an existing `SS` account after case normalization | Case-insensitive comparison occurs after account creation |
| **Dotless I / Dotted I Collision** | Turkish `ı` (U+0131, dotless i) uppercases to `I` in Turkish locale but lowercases to `i` in English. `İ` (U+0130, dotted I) lowercases to `i` in Turkish but may behave differently elsewhere | Locale-dependent case mapping; authentication uses case-insensitive comparison |
| **Kelvin Sign Collision** | `K` (U+212A, Kelvin sign) lowercases to `k` (U+006B), colliding with ASCII `K` → `k`. Used for domain/username collision attacks | Case-insensitive comparison without prior normalization to ASCII |
| **Long S Collision** | `ſ` (U+017F, long s) uppercases to `S` in some implementations, colliding with standard `s` | Similar to Eszett |
| **Sigma Collision** | Greek `Σ` (U+03A3) lowercases to either `σ` (U+03C3) or `ς` (U+03C2) depending on word position, creating asymmetric case folding | Case folding implementation doesn't account for final-sigma rule |

**Real-World Impact:** GitHub's password reset flow was exploited using a dotless-i collision — registering `John@Gıthub.com` (with dotless i) could intercept password reset emails for `john@github.com`.

### §2-4. Normalization-Induced Truncation

Some Unicode characters normalize to empty strings or are stripped during normalization, and when this occurs after length validation but before storage, it can cause unexpected truncation or boundary violations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Zero-Width Removal Truncation** | Zero-width characters (U+200B, U+200C, U+200D, U+FEFF) pass length checks but are stripped during normalization, potentially shortening strings beyond expected boundaries | Length validated pre-normalization; storage post-normalization |
| **Combining Mark Stripping** | Orphaned combining marks may be removed during normalization, altering string content | Normalization strips marks without base characters |
| **Emoji Collation Collapse** | Some databases (notably MSSQL with certain collations) treat emoji and certain Unicode graphemes as equivalent to empty strings in comparisons | Database collation doesn't properly support Unicode supplementary planes |

---

## §3. Visual Deception Mutations

Mutations that exploit the gap between what a human perceives and what the machine processes. These attacks target the human-in-the-loop component of security.

### §3-1. Homoglyph / Confusable Substitution

Characters from different Unicode scripts that are visually identical or near-identical are substituted for each other to create deceptive identifiers.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Full Script Substitution** | Entire domain or identifier uses characters from a single non-Latin script that visually resembles Latin: Cyrillic `а` (U+0430) for Latin `a` (U+0061), Cyrillic `е` for Latin `e`, etc. `аpple.com` appears identical to `apple.com` | Display system renders both scripts with visually identical glyphs |
| **Mixed Script Substitution** | Selective replacement of individual characters within an otherwise-Latin string: replacing `o` with Greek `ο` (U+03BF) or Cyrillic `о` (U+043E) | No mixed-script detection in rendering or validation |
| **Numeric Confusables** | Substitution of Arabic numerals with visually similar characters from other scripts or with modified digit forms | No confusable detection on numeric inputs |
| **Punctuation Confusables** | Replacing standard punctuation with visually identical Unicode variants: fullwidth comma, Armenian apostrophe (U+055A), modifier letter apostrophe (U+02BC) | Input validation checks for specific code points rather than character classes |

**Attack Scenarios:**
- **IDN Homograph Attack:** Registering internationalized domain names (IDN) that visually match legitimate domains. `xn--pple-43d.com` (Cyrillic `а` + Latin `pple`) displays as `аpple.com` in non-protected browsers.
- **Source Code Homoglyph:** Replacing function or variable names with homoglyph equivalents to introduce hidden backdoors that pass code review.
- **Username/Account Collision:** Registering accounts with homoglyph variants of existing usernames.

### §3-2. Bidirectional (BiDi) Text Manipulation

Unicode's Bidirectional Algorithm (UBA) controls text rendering direction using control characters (LRO, RLO, LRI, RLI, PDI, PDF, etc.). These invisible characters can reorder how text is visually displayed without changing logical byte order.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trojan Source — Reordering** | BiDi override characters (RLO U+202E, LRO U+202D) inserted into source code reorder the visual display of code lines so that what appears in a code review differs from what the compiler/interpreter processes | Code editor/reviewer renders BiDi characters; compiler processes logical order |
| **Trojan Source — Early Return** | BiDi overrides hide an early `return` statement that appears as a comment visually but is actual executable code logically | Same as above |
| **Trojan Source — Stretched String** | BiDi characters extend a string literal's visual boundary to include code that appears to be outside the string | Same as above |
| **Trojan Source — Comment Masking** | Code that appears to be inside a comment is actually outside it due to BiDi reordering | Same as above |
| **Filename BiDi Spoofing** | RLO character in filenames reverses the display of the extension: `document[RLO]fdp.exe` displays as `documentexe.pdf` | File manager/email client renders BiDi in filenames |
| **URL BiDi Spoofing** | BiDi characters in URLs make the displayed domain appear different from the actual destination | URL display does not strip or neutralize BiDi characters |

**CVE-2021-42574** tracks the Trojan Source attack class across multiple compilers and interpreters. GCC added `-Wbidi-chars` (enabled by default) as mitigation.

### §3-3. Rendering Inconsistency Exploitation

Different rendering engines, fonts, or platforms display the same Unicode sequence differently, enabling attacks that look benign on one system but malicious on another.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Font-Dependent Confusables** | Characters that are distinguishable in one font become identical in another (e.g., `l` (lowercase L) vs. `I` (uppercase i) vs. `1` (one) in monospace vs. proportional fonts) | Reviewer uses a different font/rendering than the consumer |
| **Platform-Dependent Rendering** | Emoji or special characters render differently across OS/browser combinations, potentially hiding or revealing information | Cross-platform document review |
| **Glyph Absence Fallback** | Characters missing from the active font render as blank boxes, invisible markers, or are silently dropped, changing the perceived content | Font lacks glyphs for specific Unicode ranges |

---

## §4. Invisible Character Mutations

Attacks leveraging Unicode characters that have no visible glyph but are processed as meaningful content by software systems.

### §4-1. Zero-Width Character Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Zero-Width Space (ZWSP, U+200B)** | Injected between characters in keywords to break pattern matching: `sel​ect` (with ZWSP) evades `select` keyword filter but may be stripped before SQL execution | Filter matches on raw bytes; backend strips zero-width characters |
| **Zero-Width Non-Joiner (ZWNJ, U+200C)** | Similar to ZWSP but semantically indicates a character boundary. Breaks keyword matching while being invisible | Same pattern as ZWSP |
| **Zero-Width Joiner (ZWJ, U+200D)** | Joins characters that would otherwise render separately. Can alter text semantics without visible change | Application logic affected by join behavior |
| **Word Joiner (WJ, U+2060)** | Prevents line breaks; invisible but adds length/bytes to input | Length-dependent logic (buffer allocation, truncation points) |
| **Soft Hyphen (SHY, U+00AD)** | Invisible unless a line break occurs at its position. May be stripped during processing, changing string identity | Comparison or matching occurs before/after soft hyphen stripping |

### §4-2. Unicode Tag Characters (U+E0001–U+E007F)

The Tags block (U+E0000–U+E007F) contains 128 characters that mirror ASCII but are invisible in rendering. These are increasingly weaponized for steganography and LLM prompt injection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LLM Prompt Injection** | Tag characters encode hidden instructions invisible to humans but tokenized and processed by language models. A seemingly innocent text contains embedded directives that manipulate LLM behavior | LLM processes Unicode tag characters in input; no tag-stripping in preprocessing |
| **Data Exfiltration via Tags** | Sensitive data encoded in tag characters is embedded in otherwise-innocuous output text, invisible to human reviewers but decodable by receiving software | Output sanitization does not strip tag characters |
| **Watermarking / Fingerprinting** | Tag characters embedded in text uniquely identify a copy, enabling leak tracing without visible modification | Recipient system preserves tag characters |

### §4-3. Variation Selectors (U+FE00–U+FE0F, U+E0100–U+E01EF)

Unicode designates 256 variation selector code points that modify the preceding character's glyph presentation but are otherwise invisible. They have emerged as a powerful steganographic and bypass vector.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Length Validation Bypass** | Injecting variation selectors inflates the code point count without adding visible characters. A string of 10 visible characters + 1000 variation selectors may pass a "max 20 characters" check if counted by visible glyphs but cause DoS or buffer issues at the byte level | Length check counts grapheme clusters; storage counts bytes or code points |
| **Data Smuggling in Emoji** | Arbitrary data encoded as sequences of variation selectors appended to emoji characters. Each emoji can carry up to 256 bits using VS-1 through VS-256 | Rendering shows normal emoji; extraction tool reads variation selectors |
| **Validator Bypass (CVE-2025-12758)** | The `validator` library's `isLength()` function miscounts strings containing variation selectors, reporting vastly smaller lengths than the actual byte size | Application relies on affected library for length validation |

### §4-4. Formatting and Control Characters

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Invisible Separator Injection** | Characters like U+2062 (Invisible Times), U+2063 (Invisible Separator), U+2064 (Invisible Plus) are invisible but constitute real code points | Any system that processes text length, content, or structure |
| **Interlinear Annotation Characters** | U+FFF9–U+FFFB (Interlinear Annotation Anchor/Separator/Terminator) can hide content within annotation boundaries | Rendering engine hides annotated content |
| **Object Replacement Character** | U+FFFC (Object Replacement Character) can confuse text extraction and processing pipelines | Text processing assumes character-to-glyph correspondence |

---

## §5. Best-Fit Mapping and Charset Conversion Mutations

When Unicode text is converted to a narrower encoding (e.g., UTF-8 → ANSI/Windows code pages), characters without direct equivalents are silently substituted with "best-fit" approximations. This Windows-specific behavior is a potent and underexplored attack surface.

### §5-1. Best-Fit Character Substitution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Soft Hyphen → Hyphen (CVE-2024-4577)** | The soft hyphen (U+00AD) is best-fit mapped to a standard hyphen (0x2D) on Windows. In PHP-CGI, this allowed injecting command-line arguments using `0xAD` where `-` was filtered, achieving RCE | Windows ANSI conversion via `WideCharToMultiByte()`; filter checks Unicode form only |
| **Fullwidth → ASCII Collapse** | Fullwidth characters (U+FF01–U+FF5E) best-fit map to their ASCII equivalents during ANSI conversion: `＜` → `<`, `＼` → `\`, `．` → `.` | Application receives Unicode input but passes ANSI string to filesystem or command interpreter |
| **Typographic Quote → Straight Quote** | Curly/smart quotes (U+2018, U+2019, U+201C, U+201D) map to ASCII quotes (`'`, `"`), potentially breaking SQL escaping | SQL query constructed after best-fit conversion |
| **Path Separator Smuggling** | Unicode characters that best-fit map to `\` or `/` (e.g., fullwidth solidus U+FF0F, fullwidth reverse solidus U+FF3C) bypass path validation | Path validation occurs on Unicode; filesystem access occurs on ANSI-converted path |

### §5-2. WorstFit Attack Patterns

The "WorstFit" research systematically cataloged Windows best-fit mapping exploitation into three core primitives:

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Filename Smuggling** | Unicode characters in filenames best-fit map to special characters (`..`, `/`, `\`) during ANSI conversion, enabling path traversal | Application validates Unicode filename but accesses filesystem via ANSI API |
| **Argument Splitting** | A Unicode character that best-fit maps to a space character splits what appears as a single argument into multiple arguments at the command-line level | Command construction uses Unicode; execution uses ANSI |
| **Environment Variable Confusion** | Unicode characters in environment variable names or values map to unexpected ANSI characters, altering program behavior | Environment variable lookup after ANSI conversion |

**Affected Products:** PHP-CGI (CVE-2024-4577, CVSS 9.8), ElFinder, Cuckoo Sandbox, and any Windows application using ANSI APIs for string processing.

**Root Cause:** The `WideCharToMultiByte()` Windows API with `WC_NO_BEST_FIT_CHARS` flag not set performs silent character substitution. The structural fix is to use Wide Character APIs exclusively.

---

## §6. Domain and Identifier Spoofing

Attacks targeting systems that use Unicode in identifiers — domain names, usernames, email addresses, URLs — to create confusion between distinct but visually similar entities.

### §6-1. IDN (Internationalized Domain Name) Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Whole-Script Homograph** | Domain registered entirely in a script that visually mimics Latin: `аррӏе.com` (Cyrillic) is Punycode `xn--80ak6aa92e.com` but displays as `apple.com` | Browser/client doesn't force Punycode display for whole-script non-Latin domains |
| **Mixed-Script Homograph** | Selective character substitution from multiple scripts: replacing just one letter with a confusable from another script | No mixed-script detection policy in the client |
| **Subdomain Spoofing** | Using homoglyphs in subdomain portions: `accounts.gооgle.com.evil.com` where `gооgle` uses Cyrillic `о` | Users don't verify the full domain chain |
| **TLD Homograph** | Registering domains under internationalized TLDs that visually resemble common TLDs | TLD registry permits confusable registrations |

**Browser Mitigations:** Chrome shows Punycode for mixed-script domains, single-script Cyrillic domains, and domains with confusable characters. Firefox has similar policies. However, these protections don't apply in all contexts (email clients, messaging apps, PDF viewers).

### §6-2. Email Address Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mailbox Collision via Normalization** | Email address containing Unicode characters normalizes to collide with another mailbox: `admin` with a diacritical mark normalizes to `admin` | Mail server performs normalization differently than the registration system |
| **Display Name Spoofing** | Unicode BiDi or confusable characters in the display name portion of an email make the apparent sender different from the actual address | Email client renders display name prominently; users don't verify the actual address |
| **Punycode Email Spoofing** | Email from a Punycode-encoded internationalized domain appears to come from a trusted domain | Email client converts Punycode to Unicode for display |

### §6-3. URL / URI Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HostSplit Attack** | Unicode normalization of a hostname-containing URL changes the effective host. Certain Unicode characters containing `/` or `@` in their decomposition split the URL into different host and path components after normalization | URL validation occurs before normalization; request is made after |
| **Authority Confusion** | Unicode characters in the userinfo portion of a URL (before `@`) create visual ambiguity about the actual host | URL display doesn't clearly distinguish userinfo from host |
| **Path Normalization Divergence** | Unicode characters in URL paths normalize differently in the browser vs. the server, potentially accessing different resources | Browser normalizes before sending; server normalizes differently or not at all |

---

## §7. LLM and AI-Specific Mutations

A rapidly growing category of Unicode attacks specifically targeting large language models, AI safety guardrails, and AI-powered code generation tools.

### §7-1. Invisible Prompt Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tag Character Injection** | Unicode tag characters (U+E0001–U+E007F) encode hidden instructions that LLMs process but humans cannot see. An otherwise-innocent document contains invisible directives to exfiltrate data, alter behavior, or bypass safety filters | LLM tokenizer processes tag characters; no input sanitization strips them |
| **Zero-Width Prompt Injection** | Instructions hidden using zero-width characters (ZWSP, ZWNJ, ZWJ) interspersed with or replacing visible text | LLM processes these characters at the token level |
| **Variation Selector Encoding** | Malicious instructions encoded as sequences of variation selectors appended to visible characters, using VS-1 through VS-256 as a binary encoding scheme | LLM's tokenizer preserves variation selectors |
| **Invisible Character Delimiter Injection** | Using invisible Unicode characters as delimiters between visible tokens to inject structure (e.g., system prompt boundaries) invisible to humans | LLM interprets invisible characters as meaningful separators |

### §7-2. Guardrail / Classifier Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Homoglyph Obfuscation** | Replacing characters in prohibited keywords with confusable Unicode equivalents to bypass content filters: `ЬоmЬ` (Cyrillic characters) instead of `bomb` | Safety classifier checks for exact ASCII keywords or doesn't normalize Unicode |
| **Invisible Character Splitting** | Inserting zero-width characters within prohibited words to prevent pattern matching while preserving LLM comprehension | Pattern matching is substring-based; LLM tokenization is subword-based |
| **Encoding-Level Evasion** | Using Unicode escape sequences, HTML entities, or encoded forms of prohibited content that the LLM can decode but the safety filter cannot | Safety check operates on raw text; LLM can interpret encoded content |
| **Combining Mark Obfuscation** | Adding combining diacritical marks to characters in prohibited words, changing their code points while preserving visual and semantic meaning to the LLM | Filter matches on code point sequences; LLM comprehends despite combining marks |

### §7-3. Supply Chain Attacks on AI Code Assistants

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rules File Injection** | Malicious instructions hidden in `.cursorrules`, `.github/copilot-instructions.md`, or similar AI configuration files using invisible Unicode characters | AI code assistant reads configuration files without stripping invisible characters |
| **Training Data Poisoning** | Unicode steganography in code comments or documentation that influences AI model behavior during training or in-context learning | Model training pipeline doesn't strip invisible Unicode characters |
| **Repository Manipulation** | Invisible Unicode characters in repository files (README, docs, code) that alter AI assistant behavior when processing the repository | AI tool ingests repository content without Unicode sanitization |

---

## §8. Data Integrity and Protocol-Level Mutations

Unicode mutations that affect data processing, storage, comparison, and protocol-level operations.

### §8-1. Comparison and Equality Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Normalization-Unaware Comparison** | Two strings that are canonically equivalent (NFC vs. NFD) fail equality checks because comparison operates on raw code points | Application uses byte-level or code-point-level comparison without normalization |
| **Case-Folding Asymmetry** | Case-insensitive comparison using simple case mapping disagrees with full case mapping: `ß` equals `ss` under full case folding but not simple | Inconsistent case folding across validation and lookup |
| **Collation-Based Equality** | Database collation treats certain Unicode characters as equivalent (e.g., MSSQL treating accented and unaccented characters as equal, or emoji as empty) | Database collation rules differ from application-level comparison |
| **Locale-Dependent Ordering** | Sort order changes between locales, potentially causing binary search or index lookup to fail or return incorrect results | Application assumes locale-independent ordering |

### §8-2. Length and Size Discrepancy

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Byte vs. Code Point vs. Grapheme Cluster Count** | A single visible character (grapheme cluster) can be 1–many code points and 1–many bytes. Length checks using different units give different results | Length validation uses one unit (e.g., grapheme clusters); buffer allocation uses another (e.g., bytes) |
| **Combining Character Length Inflation** | Each combining mark is a separate code point, so a single visible character with multiple combining marks occupies many code points | Code point-level length checks allow extremely long byte sequences for few visible characters |
| **Emoji Sequence Length** | Emoji with skin tone modifiers, ZWJ sequences, and flag sequences can be 1 visible glyph but 7+ code points and 28+ bytes | Size limits based on visible character count |
| **NFD Expansion** | NFC → NFD normalization can significantly increase string length in code points and bytes | Buffer sized for NFC input; content stored in NFD |

### §8-3. Database and Storage Layer Exploits

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Truncation at Charset Boundary** | When inserting Unicode text into a column with a narrower charset (e.g., UTF-8 → Latin-1), characters beyond the charset are truncated or replaced with `?`, potentially cutting strings at critical positions | Database column encoding is narrower than application encoding |
| **MySQL `utf8` vs. `utf8mb4`** | MySQL's `utf8` encoding only supports 3-byte UTF-8 (BMP only). 4-byte characters (emoji, supplementary planes) are silently truncated, potentially enabling truncation attacks | MySQL table uses `utf8` instead of `utf8mb4` |
| **Collation-Based Duplicate Key** | Two strings that differ in Unicode but are equal under the database collation cause unique constraint violations or unintended record overwrites | Database collation is less strict than application-level uniqueness checks |
| **SQL Injection via Normalization** | `U+FF07` (fullwidth apostrophe) passes input sanitization but normalizes to `U+0027` (standard apostrophe) during NFKC normalization, breaking SQL string delimiters | Sanitization occurs before normalization |

### §8-4. Unicode in Protocol Headers

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTTP Header Injection** | Non-ASCII characters in HTTP headers may be handled inconsistently across proxies and servers, enabling header injection or smuggling | Server or proxy doesn't strictly enforce ASCII-only headers per HTTP/1.1 spec |
| **SMTP/MIME Unicode Exploitation** | Unicode in email headers (Subject, From, To) interacts with MIME encoding (RFC 2047) to create parsing differences between MTAs | Different MTAs decode MIME-encoded Unicode headers differently |
| **LDAP DN Injection** | Unicode characters in LDAP Distinguished Names that normalize or fold to special characters (`,`, `+`, `"`, `\`, `<`, `>`, `;`) | LDAP library doesn't properly escape post-normalization |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **WAF / Filter Bypass** | Security filter in pipeline before application | §1 (all), §2-1, §4-1, §5-1 |
| **Authentication Bypass** | Case-insensitive username/email, normalization in auth flow | §2-3, §2-2, §3-1, §6-2 |
| **Path Traversal** | Unicode in file paths, charset conversion on filesystem access | §1-1, §1-2, §5-1, §5-2 |
| **XSS (Cross-Site Scripting)** | User input rendered in HTML after normalization | §2-1, §1-3, §5-1 |
| **SQL Injection** | Unicode input normalized/converted before SQL execution | §2-1, §1-3, §8-3 |
| **Phishing / Social Engineering** | Domain spoofing, email spoofing, filename spoofing | §3-1, §3-2, §6-1, §6-2 |
| **Source Code Supply Chain** | Code review / CI pipeline with Unicode-aware rendering | §3-2, §4-2, §7-3 |
| **LLM / AI Manipulation** | AI systems processing user-supplied Unicode text | §4-2, §4-3, §7-1, §7-2 |
| **Data Exfiltration** | Unicode steganography in output channels | §4-2, §4-3, §4-4 |
| **Denial of Service** | Length/size discrepancy, expansion attacks | §8-2, §4-3, §2-4 |
| **Remote Code Execution** | Best-fit mapping on Windows, command injection via encoding | §5-1, §5-2, §1-1 |
| **Account Takeover** | Email/username collision via normalization or case mapping | §2-3, §6-2, §8-1 |

---

## CVE / Bounty Mapping (2021–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §5-1 (Soft Hyphen Best-Fit) | CVE-2024-4577 (PHP-CGI on Windows) | CVSS 9.8. RCE via argument injection. Mass exploitation within 48 hours of disclosure |
| §1-1 (Overlong Encoding) + §1-2 | CVE-2001-0333 (IIS 4.0/5.0) | Directory traversal, arbitrary file access. Nimda worm propagation vector |
| §3-2 (BiDi Reordering) | CVE-2021-42574 (Trojan Source — multiple compilers) | Source code backdoor invisible to human reviewers. Affects C, C++, C#, JS, Java, Rust, Go, Python |
| §3-1 (Homoglyph) | CVE-2021-42694 (Trojan Source — homoglyph variant) | Function impersonation via homoglyph-renamed functions |
| §2-3 (Case Mapping Collision) | GitHub Password Reset Bypass | Account takeover via dotless-i email collision |
| §5-2 (Filename Smuggling) | CVE-2025-52488 (DNN/DotNetNuke) | Path traversal via fullwidth characters normalizing to UNC path separators |
| §4-3 (Variation Selector) | CVE-2025-12758 (validator library) | Length validation bypass; DoS and database truncation |
| §1-1 + §2-1 (Normalization) | CVE-2024-43093 (Android) | Privilege escalation via Unicode normalization bypass of file path filters |
| §1-3 (GBK Multi-Byte) | CVE-2006-2314 (MySQL/PHP) | SQL injection via multi-byte character consuming escape backslash |
| §7-3 (Rules File Injection) | Pillar Security Disclosure (2025) | Supply chain attack on GitHub Copilot / Cursor via invisible Unicode in configuration files |
| §4-2 (Tag Character Steganography) | os-info-checker-es6 npm package (2025) | Malware distribution via Unicode steganography hiding C2 payload in npm package |
| §4-2 (Tag Character Injection) | GlassWorm Campaign (2025) | 35,800+ installations compromised. Invisible Unicode characters used to hide loader code |
| §7-1 (Invisible Prompt Injection) | Microsoft Copilot ASCII Smuggling (2024) | Data exfiltration from Microsoft 365 Copilot via Unicode tag character injection |
| §6-1 (IDN Homograph) | adoḅe.com Betabot Campaign | Trojan distribution via IDN homograph domain spoofing |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Confusables Inspector** (Browser Tool) | Homoglyph / IDN attacks (§3-1, §6-1) | Client-side confusable character detection using Unicode Consortium confusables.txt |
| **ICU SpoofChecker** (Library) | Homoglyphs, mixed-script detection (§3-1) | Skeleton algorithm + mixed-script analysis per UTS #39 |
| **confusable-homoglyphs** (Python Library) | Homoglyph detection (§3-1) | Python implementation of confusable character comparison |
| **unicode-hax** (Fuzzer Library) | XSS, SQLi, encoding bypass (§1, §2, §5) | Provides security-relevant Unicode test vectors for fuzzing |
| **Shazzer** (Fuzzer) | WAF bypass, normalization (§2-1, §1) | Browser-based fuzzing of Unicode encoding and normalization behavior |
| **Recollapse** (Burp Extension) | Normalization, encoding bypass (§2, §1) | Systematic Unicode mutation generation for web application testing |
| **ActiveScan++** (Burp Extension) | General Unicode web attacks (§1–§5) | Integrates Unicode normalization and encoding test vectors into active scanning |
| **GCC `-Wbidi-chars`** (Compiler Warning) | Trojan Source / BiDi attacks (§3-2) | Detects BiDi override characters in source code. Enabled by default since GCC 12 |
| **GitHub Unicode Warning** (Platform Feature) | BiDi, invisible characters (§3-2, §4) | Alerts on hidden Unicode characters in commits and PRs |
| **StegZero** (Web Tool) | Zero-width steganography (§4-1, §4-2) | Encode/decode messages hidden in zero-width Unicode characters |
| **ASCII Smuggler** (Research Tool) | LLM prompt injection (§7-1) | Demonstrates Unicode tag character-based LLM manipulation |
| **UTS #39 Reference Implementation** (Standard) | Confusable detection (§3-1, §6) | Official Unicode Security Mechanisms — skeleton algorithm, restriction levels |

---

## Summary: Core Principles

### The Root Cause

Unicode vulnerability classes exist because Unicode is a **many-to-one** system operating in a **pipeline** architecture. The same visible character can be represented by multiple distinct code point sequences (normalization forms, encoding schemes, composed vs. decomposed). The same code point can map to different byte sequences (UTF-8, UTF-16, various ANSI code pages). And different code points can appear visually identical (confusables) or be completely invisible (zero-width, tags, variation selectors). At every stage in a processing pipeline — input reception, validation, normalization, storage, retrieval, rendering — these representations may be transformed. Security vulnerabilities arise whenever a **security decision** is made at one stage based on a representation that **changes** at a subsequent stage.

### Why Incremental Patches Fail

Each individual Unicode vulnerability can be patched: reject overlong encodings, normalize before validation, use confusable detection, strip invisible characters. But these patches address symptoms, not the structural condition. The fundamental problem is that Unicode processing is **order-dependent** and **context-dependent**, and modern software stacks have many components in the pipeline (WAF → reverse proxy → application framework → language runtime → database → filesystem → OS charset conversion), each making independent decisions about Unicode handling. A patch at one layer may be invalidated by a transformation at another layer. The WorstFit research dramatically illustrates this: even if every application correctly handles Unicode, the Windows OS-level charset conversion (`WideCharToMultiByte`) reintroduces dangerous characters.

### The Structural Solution

The only structural defense is **Unicode-aware security processing at every layer** with a consistent strategy:

1. **Normalize early:** Apply a single normalization form (preferably NFKC) at the earliest possible boundary, before any security decisions.
2. **Use wide APIs:** Never convert Unicode to narrow/ANSI encodings for security-relevant operations. On Windows, use Wide Character APIs exclusively.
3. **Validate post-normalization:** All security checks (input validation, sanitization, length checks, keyword matching) must operate on the fully normalized form.
4. **Strip invisible characters:** Remove zero-width, tag, variation selector, and BiDi override characters at input boundaries unless the application specifically requires them.
5. **Confusable detection:** For user-facing identifiers (usernames, domains, email), implement UTS #39 confusable detection with restriction level enforcement.
6. **Consistent encoding throughout:** Use UTF-8 (or UTF-16) end-to-end, including database columns (`utf8mb4` in MySQL), filesystem operations, and all intermediary processing. Never mix character encodings across a pipeline.

These principles must be applied **at every component boundary** in the stack, not just at the application layer. Unicode security is a systems problem, not an application problem.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- Unicode Technical Standard #39: Unicode Security Mechanisms — https://unicode.org/reports/tr39/
- RFC 3629: UTF-8, a transformation format of ISO 10646
- "Trojan Source: Invisible Vulnerabilities" — Boucher & Anderson, USENIX Security 2023
- "Host/Split: Exploitable Antipatterns in Unicode Normalization" — Birch, Black Hat USA 2019
- "Lost in Translation: Exploiting Unicode Normalization" — Black Hat 2025
- "WorstFit: Unveiling Hidden Transformers in Windows ANSI" — DEVCORE, 2025
- OWASP Unicode Encoding Attack Reference
- CWE-176: Improper Handling of Unicode Encoding
- CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic
- "Unicode Security Software Vulnerability Testing Guide" — Weber, Black Hat USA 2009
- "Weaponising Unicode for Fun and Profit" — Lim, GovTech CSG
- "WAF Bypassing with Unicode Compatibility" — Lajara
- "Sneaky Bits: Advanced Data Smuggling Techniques" — Embrace The Red, 2025
- "Imperceptible Jailbreaking against Large Language Models" — arXiv, 2025
- AWS Security Blog: "Defending LLM Applications Against Unicode Character Smuggling"
