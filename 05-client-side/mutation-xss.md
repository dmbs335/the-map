# Mutation XSS (mXSS) Mutation/Variation Taxonomy

---

## Classification Structure

Mutation XSS (mXSS) is a class of cross-site scripting that exploits **discrepancies between how HTML sanitizers parse markup and how browsers reconstruct the DOM**. Unlike traditional XSS where the payload is directly malicious, mXSS payloads appear benign during sanitization but become dangerous after the browser's HTML parser mutates the DOM structure during rendering. The fundamental principle underlying all mXSS is **parser non-idempotency**: `P(P(D)) != P(D)` — parsing an HTML string, serializing the result, and re-parsing does not guarantee the same DOM tree.

This taxonomy organizes the mXSS attack surface across three orthogonal axes:

**Axis 1 — Mutation Mechanism (Primary Axis):** The structural HTML parsing behavior that causes the DOM to differ between sanitization and rendering. This determines *how* the mutation occurs and is the single most important factor in understanding and discovering mXSS variants.

**Axis 2 — Discrepancy Origin (Cross-Cutting Axis):** The architectural reason *why* the sanitizer and browser produce different DOM trees. Each origin type can apply across multiple mutation mechanisms.

**Axis 3 — Exploitation Scenario (Impact Axis):** The real-world application context where mXSS achieves code execution — from email clients to CMS platforms to single-page applications.

### Axis 2 Summary: Discrepancy Origin Types

| Discrepancy Type | Mechanism | Applicable Across |
|---|---|---|
| **Serialize-Parse Roundtrip** | HTML serialization followed by re-parsing produces a different DOM tree — the WHATWG spec explicitly acknowledges this non-idempotency | §1, §2, §3, §4, §5 |
| **Parser Differential** | Sanitizer uses a different parsing algorithm than the browser (e.g., XML parser vs. HTML5 parser, DOMParser with scripting disabled vs. browser with scripting enabled) | §1, §3, §4, §6 |
| **Context Switching** | Developer inadvertently changes the rendering context between sanitization and insertion (e.g., sanitizes as HTML body fragment, renders inside SVG) | §1, §2, §3 |
| **Desanitization** | Application modifies the sanitizer's output before rendering — any post-processing change to markup can re-introduce dangerous structures | §7 |

### Foundational Concept: The Serialize-Parse Roundtrip

The WHATWG HTML specification explicitly warns:

> *"It is possible that the output of this algorithm, if parsed with an HTML parser, will not return the original tree structure."*

This non-idempotency is the root cause of mXSS. HTML sanitizers typically:

1. **Parse** the input string into a DOM tree (first parse)
2. **Walk** the tree and remove dangerous nodes/attributes
3. **Serialize** the clean tree back to an HTML string
4. The application **inserts** this string into the page via `innerHTML` or similar
5. The browser **re-parses** the string (second parse) — producing a **different** DOM tree

The mutation occurs at step 5. The sanitizer operated on the DOM from step 1, but the user's browser builds a different DOM in step 5 due to context-sensitive parsing rules, error recovery, and namespace switching. The attacker's goal is to craft input where the step-1 DOM is safe but the step-5 DOM contains executable JavaScript.

---

## §1. Namespace Switching Mutations

Exploiting the transitions between HTML, SVG, and MathML namespaces, where parsing rules differ fundamentally. This is the most prolific and dangerous category of mXSS, responsible for the majority of sanitizer bypasses since 2019.

HTML5 defines three namespaces: **HTML**, **SVG**, and **MathML**. Each namespace has different rules for how elements and their children are parsed. The critical differences:

- In **HTML namespace**, `<style>` children are treated as **RAWTEXT** (plain text, no child elements, no entity decoding)
- In **SVG/MathML namespace**, `<style>` children are treated as **regular elements** (child elements parsed, entities decoded)
- **HTML integration points** (`<foreignObject>`, `<desc>`, `<title>` in SVG; `<annotation-xml>` with specific encoding in MathML) switch parsing back to HTML rules
- **MathML text integration points** (`<mi>`, `<mo>`, `<mn>`, `<ms>`, `<mtext>`) allow HTML elements to be parsed inside MathML

### §1-1. HTML-to-MathML Namespace Switch

The most common mXSS vector. Content enters the MathML namespace where `<style>` is no longer RAWTEXT, causing the browser to parse its "text" children as active elements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **mglyph/malignmark integration point escape** | `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>` — The `<mglyph>` element inside `<mtext>` is an HTML integration point. On first parse, the `<style>` content appears as text. On re-parse, namespace boundaries shift and the `<img>` escapes the style context | Sanitizer does not model MathML text integration points; DOMPurify < 2.0.17 |
| **mtext-style reparse** | `<math><mtext><style><img src=x onerror=alert(1)></style></mtext></math>` — In MathML, `<style>` permits child elements. The sanitizer sees the `<img>` as inert style text; the browser parses it as a live element after namespace context changes | Browser re-parses serialized MathML `<style>` content as HTML |
| **Nested form collapse in MathML** | Nested `<form>` elements are invalid in HTML. During re-parsing, the browser collapses nested forms, shifting remaining elements across namespace boundaries. Elements previously inside a safe MathML context land in HTML context where they become active | Nested `<form>` elements combined with MathML integration points |

### §1-2. HTML-to-SVG Namespace Switch

SVG namespace parsing creates similar opportunities to MathML, with `<style>` and other RAWTEXT elements behaving differently.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG style child mutation** | `<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">` — The `</p>` triggers HTML error recovery that closes the `<svg>` context prematurely. During re-parse, the `<style>` content shifts from SVG (where children are elements) to HTML (where children are text), or vice versa, exposing the payload | Sanitizer and browser disagree on when the SVG context ends |
| **SVG foreignObject content escape** | `<svg><foreignObject><body onload=alert(1)>` — `<foreignObject>` is an HTML integration point. Content inside it is parsed as HTML. When a sanitizer removes `<foreignObject>` but preserves its children, the children shift to SVG namespace where they behave differently | Sanitizer strips `<foreignObject>` but retains children |
| **SVG desc/title integration point** | `<svg><desc><style><img src=x onerror=alert(1)></style></desc></svg>` — `<desc>` and `<title>` in SVG are HTML integration points. The `<style>` inside an integration point follows HTML RAWTEXT rules on first parse but may switch to SVG element rules on re-parse | Namespace context ambiguity at integration point boundaries |

### §1-3. SVG-to-MathML Cross-Namespace Chaining

Nesting SVG and MathML creates compound namespace transitions where the cumulative effect is unpredictable.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Triple-namespace nesting** | Payloads chain HTML → MathML → SVG (or reverse) transitions. Each transition changes parsing rules, and the serialization of the intermediate DOM doesn't preserve the exact namespace context. On re-parse, elements land in different namespaces than the sanitizer expected | Multiple nested foreign content elements with integration points |
| **annotation-xml encoding switch** | `<math><annotation-xml encoding="text/html">` creates an HTML integration point inside MathML. Content after this element is parsed as HTML, but the sanitizer may still apply MathML rules | `annotation-xml` with `text/html` or `application/xhtml+xml` encoding attribute |

### §1-4. Namespace-Sensitive Comment Mutation

HTML comments behave differently across namespaces, creating mutation vectors.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Comment in MathML style** | `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">` — The sanitizer sees `<!--` as opening a comment within the MathML `<style>`. After serialization and re-parse, the comment boundaries shift, and the `<img>` escapes the comment | DOMPurify checked text nodes but not comment nodes (patched in 2.1) |
| **CDATA in foreign content** | `<math><mtext><table><mglyph><style><![CDATA[</style><img onerror=alert(1) src>">` — CDATA sections are valid in SVG and MathML but not in HTML. The sanitizer may preserve CDATA, but the browser's HTML parser interprets it differently on re-parse | CDATA valid in foreign content but not in HTML re-parse context; Firefox-specific |
| **Closing bang comment (`--!>`)** | HTML accepts `--!>` as a valid comment closer (in addition to `-->`). A sanitizer that does not recognize this treats `<!-- c--!><img onerror=alert(1) src>-->` as a single comment, while the browser closes the comment at `--!>` and activates the `<img>`. The payload is smuggled through the comment boundary. CVE-2022-36020 (Typo3), also bypassed AntiSamy and HtmlRuleSanitizer | Sanitizer's HTML parser does not implement the non-standard `--!>` comment close syntax from the WHATWG spec |

---

## §2. Element Rearrangement Mutations

Exploiting the HTML parser's error recovery algorithms that move, remove, or restructure elements during tree construction. These mutations change the **parent-child relationships** of DOM nodes.

### §2-1. Foster Parenting

The HTML specification's "foster parenting" algorithm handles invalid content inside `<table>` elements by moving misplaced children *before* the table in the DOM tree.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Table child promotion** | `<table><style><img src=x onerror=alert(1)></style></table>` — `<style>` is not valid as a direct child of `<table>`. The parser "foster parents" it to before the table. During re-parse, the `<style>` content (previously inert inside the table) becomes active HTML | Parser rearranges `<style>` from inside table to before table, changing context |
| **Table-mglyph foster chain** | `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>` — The `<table>` triggers foster parenting, moving `<mglyph>`, `<style>`, and `<img>` before the table. Combined with MathML namespace switch, the foster-parented elements change namespace | MathML context + table foster parenting |
| **xmp/noembed in table** | `<table><xmp><td></xmp>` — RAWTEXT elements inside tables are foster-parented. After rearrangement, the element boundaries shift and previously-escaped content becomes active | RAWTEXT element misplaced inside table |

### §2-2. Adoption Agency Algorithm

The HTML parser's "adoption agency algorithm" handles improperly nested formatting elements by restructuring the DOM tree.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Misnested formatting elements** | `<b><i></b></i>` → browser restructures nesting, creating `<b><i></i></b><i></i>`. If attacker-controlled content falls within the restructured region, it may shift from a safe to a dangerous parent context | Misnested `<b>`, `<i>`, `<a>`, `<font>`, `<s>`, `<u>`, etc. |
| **Anchor tag reconstruction** | `<a href="safe"><a href="javascript:alert(1)">click</a></a>` — Nested `<a>` tags are invalid. The adoption agency algorithm closes the first and opens the second, potentially changing which href is active | Duplicate anchor tag reconstruction |

### §2-3. Nested Form Collapse

HTML prohibits nested `<form>` elements. The parser silently discards the inner form's start tag, collapsing the structure.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form nesting content escape** | `<form id="outer"><div></form><form id="inner"><input>` — After serialization, the DOM shows two forms. On re-parse, the inner `<form>` tag is ignored (HTML doesn't allow nested forms), and the `<input>` associates with the outer form. Content boundaries shift during this collapse | Nested `<form>` elements that collapse on re-parse |
| **Form-math integration** | Nested forms combined with MathML elements create compound mutations: form collapse changes the nesting depth, which shifts MathML/HTML namespace boundaries | `<form>` inside `<math><mtext>` with subsequent `<form>` |

---

## §3. Text Content Mode Confusion

Exploiting the different text parsing modes in HTML — **Data** (normal), **RAWTEXT** (no child elements, no entity decoding), **RCDATA** (no child elements, entities decoded), and **PLAINTEXT** (all remaining content is text).

### §3-1. RAWTEXT Element Confusion

Elements like `<style>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>` parse their content as RAWTEXT in HTML — but may not in other namespaces or parser configurations.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Style in foreign content** | `<style>` in HTML namespace: children are RAWTEXT (inert text). `<style>` in SVG/MathML namespace: children are parsed as elements (active). If serialization doesn't preserve the namespace, re-parsing changes the mode | Namespace changes between sanitization parse and browser re-parse (see §1) |
| **xmp element exploitation** | `<table><xmp><td>` — `<xmp>` is RAWTEXT in HTML. When combined with foster parenting or namespace switching, the xmp boundaries shift, and content that was text becomes active HTML | `<xmp>` foster-parented out of table context |
| **noembed/noframes as HTML smuggling** | `<noembed>&lt;img src=x onerror=alert(1)&gt;</noembed>` — Some parsers (XML-style) treat `<noembed>` content as HTML with entity decoding. The browser decodes entities inside noembed and may activate the resulting markup on re-parse | XML-style parser vs. HTML5 parser differential on RAWTEXT elements |

### §3-2. RCDATA Element Confusion

`<textarea>` and `<title>` parse content as RCDATA — HTML entities are decoded but no child elements are created.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **textarea element escape** | `<textarea>&lt;script&gt;alert(1)&lt;/script&gt;</textarea>` — In RCDATA mode, entities are decoded but children aren't parsed. If the context changes (e.g., serialized and placed in a non-RCDATA context), the decoded entities become active markup | RCDATA content serialized into non-RCDATA context |
| **title tag in SVG vs HTML** | `<svg><title>` is an HTML integration point. Content inside it follows HTML rules. But `<title>` in HTML is RCDATA. If the parser disagrees about whether `<title>` is in SVG or HTML context, content parsing differs | SVG `<title>` as integration point vs. HTML `<title>` as RCDATA |

### §3-3. noscript Parsing Differential

The `<noscript>` element behaves fundamentally differently based on whether JavaScript is enabled or disabled.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **noscript scripting-flag differential** | `<noscript><style></noscript><img src=x onerror=alert(1)>` — When scripting is **disabled** (as in DOMParser/sanitizer), `<noscript>` content is parsed as HTML elements. When scripting is **enabled** (browser rendering), content is treated as RAWTEXT. The sanitizer sees a `<style>` element; the browser sees raw text followed by an `<img>` | Sanitizer parses with scripting disabled; browser renders with scripting enabled |
| **noscript in lxml/server-side** | Server-side sanitizers using lxml or similar HTML parsers parse `<noscript>` content as HTML (scripting-disabled behavior). The browser ignores it as RAWTEXT (scripting-enabled), and content after `</noscript>` becomes active | Server-side sanitizer (lxml, Bleach) vs. client-side rendering; CVE-2020-6802 |

---

## §4. Encoding and Entity Processing Mutations

Exploiting differences in how character entities, character encoding, and escape sequences are handled between parse passes.

### §4-1. HTML Entity Decoding Across Namespaces

HTML entities are decoded differently depending on the parsing context and namespace.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Entity decoding in foreign style** | In MathML/SVG, `<style>` content allows entity decoding (children are elements, not RAWTEXT). `&lt;img src=x onerror=alert(1)&gt;` inside a MathML `<style>` gets decoded to `<img src=x onerror=alert(1)>` on re-parse | MathML/SVG `<style>` element with encoded entities |
| **Entity nesting across passes** | `&amp;lt;` → `&lt;` → `<` after multiple parse-serialize-reparse cycles. Each pass decodes one layer of entities | Multiple sanitization/rendering passes; double-encoding scenarios |

### §4-2. Attribute Value Entity Mutation

Attribute values undergo entity decoding during serialization, which can change their meaning on re-parse.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Title attribute breakout** | `<img title="&lt;img src=x onerror=alert(1)&gt;">` — After serialization, the browser may decode the entities in the title attribute. If the serialized string is re-parsed in a different context, the decoded attribute value becomes active markup | Attribute value containing encoded markup placed in non-attribute context on re-parse |
| **Encoded attribute in comment** | Combining HTML comments with entity-encoded attribute values creates payloads where the comment boundary and attribute boundary interact differently across parse passes | Comment-attribute boundary ambiguity |

### §4-3. Character Encoding Mismatch

Differences in character encoding between sanitization and rendering environments.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **UTF-7 content interpretation** | `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` — If the rendering context uses UTF-7 auto-detection, the encoded content becomes active HTML | Missing charset declaration; legacy browser auto-detection |
| **Charset mismatch mutation** | Sanitizer processes as UTF-8; browser renders as Shift_JIS or EUC-JP. Multi-byte sequences in one encoding consume delimiter characters in another, breaking parsing boundaries | Content-Type charset mismatch between sanitizer and renderer |

---

## §5. Structural Depth and Nesting Mutations

Exploiting browser limits on DOM tree depth and the structural consequences of exceeding those limits.

### §5-1. Nesting Depth Limit Exploitation

Browsers impose maximum nesting depth limits (typically 512 elements in Chromium). Exceeding this limit causes the browser to flatten the DOM structure.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Deep nesting node flattening** | Hundreds of nested `<div>` elements followed by a malicious element. The sanitizer processes all nesting levels normally. The browser hits its depth limit and flattens the tree, moving deeply-nested content to a shallower level where it becomes active | DOMPurify < 3.1.3 (CVE-2024-47875); browser nesting limit reached |
| **Nesting-based tag escape** | Deep nesting causes the browser to ignore some closing tags, leaving elements unclosed that the sanitizer expected to be closed. Subsequent content falls into an unexpected parent context | Browser-specific nesting depth limits; varies by engine |

### §5-2. Tree Depth Truncation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Parser max-depth divergence** | Sanitizer library has no depth limit (or a different one) vs. browser's limit. Trees that the sanitizer considers valid are truncated by the browser, changing parent-child relationships | Sanitizer depth limit != browser depth limit |

---

## §6. Parser Algorithm Differentials

Exploiting fundamental differences between the parsing algorithm used by the sanitizer and the browser's HTML5 parser.

### §6-1. XML vs. HTML Parser Differential

Some sanitizers use XML-based parsing (or hybrid approaches) while browsers use HTML5 parsing, leading to systematic disagreements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Self-closing tag interpretation** | In XML, `<div/>` is self-closing. In HTML5, `<div/>` is treated as `<div>` (not self-closing for non-void elements). Content after `<div/>` falls outside the div in XML but inside it in HTML5 | Sanitizer uses XML parser; browser uses HTML5 parser |
| **CDATA section handling** | `<![CDATA[...]]>` is valid in XML but treated as a bogus comment in HTML. Content inside CDATA may be active in one parser and inert in the other | XML-based sanitizer vs. HTML5 browser parser |
| **Namespace handling** | XML parsers support explicit namespace prefixes (`<svg:rect>`). HTML5 parsers only recognize `<svg>` and `<math>` as namespace-switching elements. Different namespace assignment changes how children are parsed | Explicit vs. implicit namespace handling |

### §6-2. DOMParser Scripting Flag Differential

JavaScript's `DOMParser` creates a document with **scripting disabled**, while the browser's rendering context has **scripting enabled**. This creates systematic parsing differences for scripting-dependent elements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **noscript differential** (see §3-3) | `<noscript>` content is HTML elements when scripting is disabled, RAWTEXT when enabled | Sanitizer uses DOMParser (scripting off); rendering has scripting on |
| **script element content** | In scripting-disabled context, `<script>` content may be treated differently than in scripting-enabled context | Sanitizer processes `<script>` as disabled; browser processes as enabled |

### §6-3. Lexical Parser State Exploitation (LEXSS)

Custom sanitizers using lexer-based parsing (not DOM-based) have tokenization-level disagreements with the browser.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Token boundary differential** | Custom lexer interprets token boundaries (tag start, attribute delimiter, comment boundary) differently than the browser's tokenizer state machine | Custom sanitizer with non-standard tokenizer |
| **State machine desynchronization** | Input causes the sanitizer's lexer state machine to enter a different state than the browser's. Subsequent input is classified as different token types (tag vs. text vs. comment) | Sanitizer uses hand-written tokenizer; edge cases in HTML tokenization spec |

---

## §7. Desanitization (Post-Processing Mutations)

Applications that modify the sanitizer's output before rendering — any structural change to the sanitized markup can undo the sanitization by altering how the browser parses it.

### §7-1. Element Rename/Unrename

Applications that rename dangerous elements before sanitization and restore them afterward.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG/MathML tag renaming** | Application renames `<svg>` to `<proton-svg>` before DOMPurify, then restores it after. DOMPurify doesn't recognize `<proton-svg>` as dangerous. After restoration, the `<svg>` activates namespace switching and event handlers that DOMPurify had not neutralized | Proton Mail, Skiff (2023); any custom pre/post-processing around a sanitizer |
| **Attribute stripping and restoration** | Application strips certain attributes before sanitization, then re-adds them. The re-added attributes may contain event handlers or dangerous values | Custom sanitizer pipeline with attribute manipulation |

### §7-2. String Replacement on Sanitized Output

Text-level manipulation of the sanitized HTML string before it is inserted into the DOM.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Regex replacement on sanitized HTML** | `sanitized.replace(/something/g, 'replacement')` — The replacement changes tag boundaries, attribute delimiters, or namespace contexts. Even removing a single character can alter the DOM tree on re-parse | Any string manipulation after sanitization |
| **Template insertion** | Sanitized HTML inserted into a larger template via string concatenation. The surrounding template context changes how the sanitized fragment is parsed | Template wrapping changes the parser's insertion mode |

### §7-3. Context Relocation

Moving sanitized content from the context it was sanitized for into a different rendering context.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Body-to-SVG context switch** | Content sanitized assuming it will be inserted as HTML body content is instead placed inside an `<svg>` element. Parsing rules differ — `<style>` changes from RAWTEXT to element-container | Developer inserts sanitized HTML into foreign content context |
| **Document-to-fragment context** | Sanitizer parses with no context element (defaults to `<body>`). Application inserts result into a different element (e.g., `<table>`, `<select>`) where parsing rules differ | Context element mismatch between sanitization and rendering |

### §7-4. Serializer-Induced Mutation (Coercion)

The sanitizer's own serialization step can transform benign input into a dangerous payload — the sanitizer *creates* the vulnerability rather than failing to prevent it. Systematic testing across 11 sanitizers found 19,843 payloads that did not execute on their own but became dangerous only *after* passing through sanitization ("coercion attacks").

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Character reference decoding without re-encoding** | The sanitizer's parser decodes character references (`&lt;` → `<`) as required by the HTML spec, but the serializer fails to re-encode them in the output. A harmless encoded payload (`&lt;img onerror=alert(1)&gt;`) is decoded during parsing and output as active markup | Sanitizer does not re-encode decoded character references in text nodes, attributes, or comments during serialization |
| **Failure to encode text values** | Content parsed as text (inside RAWTEXT/RCDATA elements) is not entity-encoded during serialization. If a parsing differential causes the browser to interpret the element differently, the unencoded text becomes active markup | Sanitizer does not encode text content from elements whose parsing mode differs between sanitizer and browser |

---

## §8. Configuration and API Misuse Mutations

Exploiting specific sanitizer configuration options or API usage patterns that weaken mXSS protection.

### §8-1. DOMPurify Configuration Weaknesses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SAFE_FOR_TEMPLATES regex bypass** | When `SAFE_FOR_TEMPLATES` is enabled, DOMPurify uses a regex to strip template delimiters. Incorrect regex fails to catch edge cases with SVG elements, allowing mXSS (CVE-2025-26791) | `SAFE_FOR_TEMPLATES: true` with custom element handling |
| **CUSTOM_ELEMENT_HANDLING permissive regex** | `tagNameCheck: /.*/` with `FORBID_CONTENTS: [""]` allows `<annotation-xml>` and `<foreignObject>` elements that facilitate namespace transitions | Overly permissive custom element configuration |
| **RETURN_DOM misuse** | Developers who use `RETURN_DOM` or `RETURN_DOM_FRAGMENT` avoid the serialize-parse roundtrip (good). But those who serialize the result back to string (`innerHTML`) reintroduce the vulnerability | Using `RETURN_DOM` but then serializing to string |
| **WHOLE_DOCUMENT mode** | Processing in whole-document mode changes the parser's insertion mode, potentially allowing elements that would be rejected in fragment mode | `WHOLE_DOCUMENT: true` with user-controlled input |

### §8-2. Server-Side Sanitizer Limitations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **No namespace support** | Server-side sanitizers parse everything as HTML, unable to model SVG/MathML namespace transitions. Payloads using namespace switching pass through undetected. Systematic testing of 11 sanitizers across 5 languages (DOMPurify/jsdom, sanitize-html, HtmlSanitizer, HtmlRuleSanitizer, Typo3 html-sanitizer, rgrove/sanitize, loofah, AntiSamy, JSoup, lxml_html_clean, Bleach) found that no server-side sanitizer correctly implements namespace transition rules | Server-side sanitizer without foreign content support; CVE-2024-52595 (lxml) |
| **RCDATA element ignorance** | Server-side parser treats `<noscript>`, `<noembed>` content differently than the browser due to missing scripting-flag context | Server-side parser cannot know client's scripting state |
| **Encoding mismatch** | Server sanitizes with one character encoding assumption; client renders with another. Multi-byte character sequences consume or create delimiters | Encoding not explicitly synchronized between server and client |

### §8-3. Browser-Native Sanitizer API Bypasses

Bypasses targeting the browser's built-in Sanitizer API (`setHTML()`), which eliminates the serialize-parse roundtrip but may still have allowlist gaps for resource reference elements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG `<use href>` element bypass** | `<svg><use href="//target.com/uploaded-malicious.svg#x"/></svg>` — The Sanitizer API blocks SVG imports via `data:` and relative URLs but permits same-origin absolute URLs in `<use href>`. An attacker uploads a malicious SVG file to the target origin (e.g., via file upload endpoint), then references it with an absolute URL. The `Content-Disposition: attachment` header on the uploaded file does not prevent SVG `<use>` reference processing. The core issue is that the Sanitizer API allowlist did not account for how browsers actually process absolute-URL SVG references, allowing attacker-controlled SVG content to be composed into the page | Firefox Sanitizer API implementation (2022); target origin must accept SVG file uploads |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Email Client XSS** | Webmail rendering HTML emails (Proton Mail, Tutanota, Skiff, Outlook Web) | §1 + §7 — Namespace switching + desanitization via element renaming |
| **CMS/Rich Text Platform** | WordPress, Joomla, Drupal, Notion, Confluence rendering user content | §1 + §2 + §3 — Namespace switching + foster parenting + text mode confusion |
| **Markdown Renderer** | Markdown-to-HTML libraries with sanitization (marked, markdown-it, showdown) | §6 + §3 — Parser differential + noscript confusion |
| **Forum/Comment System** | User-generated HTML content with allowlisted tags | §1 + §2 + §5 — Namespace + element rearrangement + nesting depth |
| **Single-Page Application** | React/Vue/Angular apps using `innerHTML` or `v-html` with sanitized content | §1 + §8 — Namespace switching + DOMPurify misconfiguration |
| **Collaborative Document Editor** | Google Docs-like editors sanitizing paste content or imported HTML | §2 + §7 — Element rearrangement + desanitization |
| **Healthcare/EHR System** | Clinical content rendering (HL7 CDA, CCDA) with embedded HTML | §6 + §4 — XML/HTML parser differential + entity mutation |
| **Enterprise Chat** | Slack, Teams, Discord rendering formatted messages | §1 + §3 + §8 — Namespace + text mode + sanitizer config |
| **CTF/Security Challenge** | Intentionally vulnerable sanitizers for security competitions | All categories — Full attack surface exploration |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 (MathML mglyph namespace switch) | DOMPurify < 2.0.17 (Securitum, 2020) | Full sanitizer bypass; arbitrary JS execution in all DOMPurify-dependent apps |
| §1-2 (SVG style mutation) | DOMPurify < 2.0.1 (Securitum, 2019) | Chrome 77 mXSS via `<svg></p><style>` mutation |
| §1-4 (Comment mutation in MathML) | DOMPurify < 2.1 (PortSwigger, 2020) | Comment-based mXSS bypass; text node check didn't cover comments |
| §1-4 (CDATA in foreign content) | DOMPurify < 2.1 Firefox variant (PortSwigger, 2020) | Firefox-specific CDATA-based mXSS bypass |
| §5-1 (Nesting depth flattening) | CVE-2024-47875 (DOMPurify < 3.1.3) | Nesting-based mXSS; critical severity |
| §8-1 (Template regex bypass) | CVE-2025-26791 (DOMPurify < 3.2.4) | Incorrect template literal regex; mXSS when `SAFE_FOR_TEMPLATES` enabled |
| §8-1 (Custom element handling) | DOMPurify 3.0.8 bypass (kevin mizu, 2024) | Permissive `CUSTOM_ELEMENT_HANDLING` + emptied `FORBID_CONTENTS` |
| §3-3 (noscript scripting-flag) | CVE-2020-6802 (Bleach) | mXSS via noscript parsing differential; Bleach deprecated partly due to this class |
| §3-3 (noscript + RCDATA in math) | CVE-2020-6816 (Bleach) | mXSS when math/SVG tags whitelisted with RCDATA tags and `strip=False` |
| §8-2 (No namespace support) | CVE-2024-52595 (lxml_html_clean) | lxml parses all content as HTML; namespace-based mXSS bypasses undetected |
| §6-1 (XML parser differential) | DOMPurify XML mode bypass (Flatt Security, 2024) | Bypassing DOMPurify with good old XML; namespace handling differences |
| §7-1 (Element rename/unrename) | Proton Mail XSS (SonarSource, 2023) | Email reading XSS via svg tag renaming; email content theft, impersonation |
| §7-1 (Element rename/unrename) | Skiff Mail XSS (SonarSource, 2023) | Same desanitization pattern; email account compromise |
| §7-1 (Desanitization) | Tutanota XSS (SonarSource, 2023) | Post-sanitization markup manipulation enabling XSS |
| §7-1 (Desanitization) | Mailspring XSS (SonarSource, 2023) | Desktop email client mXSS via desanitization |
| §7-1 (Desanitization) | osTicket XSS (SonarSource, 2023) | Support ticket system XSS via desanitization |
| §6-1 (Self-closing tag differential) | CVE-2022-36033 (jsoup) | jsoup sanitizer bypass when `preserveRelativeLinks` enabled |
| §1-3 (annotation-xml integration) | Google Caja bypass (historical) | Namespace confusion in Google's HTML sanitizer; Google Search impacted |
| §8-1 (TYPO3 sanitizer bypass) | TYPO3 html-sanitizer (2023) | HTML comment malformation + CDATA section bypass |
| §1-4 (Bang comment) + §8-2 (PI 4 CDATA) | CVE-2022-23499 (Typo3 html-sanitizer) | CDATA parsing differential + namespace confusion; two separate vulnerabilities grouped into one CVE |
| §1-4 (Bang comment `--!>`) | CVE-2022-36020 (Typo3 html-sanitizer) | Closing bang comment not detected; payload smuggled through comment boundary |
| §3-3 (noscript scripting-flag) | CVE-2023-38500 (Typo3 html-sanitizer) | noscript content parsed as HTML instead of text |
| §1-4 (Comment + text content) | CVE-2023-43643 (AntiSamy) | Tags with text content not closed when containing a comment; attacker escapes attribute context |
| §3-3 (noscript + namespace) | CVE-2023-23627 (rgrove/sanitize, Ruby) | noscript content parsed as markup instead of text |
| §7-4 (Serializer coercion) | DOMPurify jsdom 19 (Parse Me Baby, 2024) | Serializer decodes and reflects text content; benign payloads become dangerous after sanitization |
| §8-1 (Google Closure bypass) | closure-library sanitizer (2020) | noscript + title attribute escaping bypass |
| §8-3 (SVG `<use href>` allowlist gap) | Firefox Sanitizer API bypass (PortSwigger, 2022) | SVG `<use href>` with same-origin absolute URL bypasses Sanitizer API allowlist; attacker-uploaded SVG composed into page |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **DOMPurify** (Sanitizer) | mXSS prevention | DOM-based sanitization; avoids serialize-parse roundtrip when using `RETURN_DOM`; regularly patched for new mXSS vectors |
| **Sanitizer API** (Browser Built-in) | mXSS prevention | Browser-native `setHTML()` avoids roundtrip entirely by building DOM directly; immune to mXSS by design but subject to allowlist gaps (e.g., SVG `<use href>` bypass in Firefox, see §8-3) (Chrome Canary, Firefox Nightly) |
| **MutaGen** (Research) | Server-side sanitizer bypass via parsing differentials | HTML fragment generator focused on mutation-prone structures (23 transformations); tests 11 sanitizers across 5 languages. Found 16 bypasses and 19,843 coercion payloads (Parse Me Baby, IEEE S&P 2024) |
| **Sanity Fuzzer** (Research) | Sanitizer mXSS | Differential testing: sanitize HTML, compare sanitizer DOM vs. browser `innerHTML` DOM for mutations |
| **SonarSource mXSS Cheatsheet** (Reference) | mXSS payloads | Curated payload database organized by sanitizer and version with explained mechanisms |
| **msrkp/MXSS** (Reference) | mXSS payloads | Awesome mXSS collection with evolution timeline and categorized payloads |
| **Burp Suite Scanner** (Commercial) | mXSS via sanitizer bypass | Active scanning with mutation payload generation and DOM-based verification |
| **DOM Invader** (Burp Extension) | DOM-based mXSS | Automated DOM source-to-sink analysis including `innerHTML` sink with sanitizer detection |
| **Browser DevTools** | Manual mXSS research | Direct comparison of DOMParser output vs. `innerHTML` re-parse output |

---

## Summary: Core Principles

**What makes mXSS possible.** The fundamental property that enables mXSS is **HTML's context-dependent, error-recovering parser combined with the serialize-parse roundtrip**. HTML5 parsing is deterministic but not idempotent — the same string parsed in different contexts (different parent element, different namespace, different scripting flag) produces different DOM trees. Sanitizers must predict what the browser's parser will produce, but they parse in a different environment (different context element, scripting disabled, potentially different parser implementation). This prediction gap is inherently unfixable through sanitizer improvements alone because the sanitizer cannot know the exact context in which its output will be rendered.

**Why incremental patches fail.** Each DOMPurify bypass follows a pattern: a researcher discovers a new mutation vector, the maintainer adds a specific check, and the next researcher finds a mutation the new check doesn't cover. This is not a failure of DOMPurify's engineering — it's a fundamental property of the problem space. The HTML specification defines different parsing rules for three namespaces, multiple text content modes (RAWTEXT, RCDATA, PLAINTEXT), scripting-dependent behavior, and extensive error recovery. The combinatorial space of nesting patterns, namespace transitions, and context interactions is vast enough that no sanitizer can model all possible browser behaviors through blacklisting individual mutation patterns. The approximately 1,500 pages of HTML parsing specification create an attack surface that dwarfs any sanitizer's test coverage.

**What structural defense looks like.** The only architecturally sound defense against mXSS is **eliminating the serialize-parse roundtrip**. This can be achieved through: (1) using `RETURN_DOM` / `RETURN_DOM_FRAGMENT` in DOMPurify to pass DOM nodes directly without serialization, (2) adopting the browser-native **Sanitizer API** (`setHTML()`) which builds the sanitized DOM directly without intermediate string serialization, or (3) using **Trusted Types** to prevent strings from reaching `innerHTML` and similar sinks. The Sanitizer API is the definitive solution — by having the browser itself perform sanitization using its own parser, the parser differential problem is eliminated by definition. Until the Sanitizer API achieves universal browser support, the combination of `DOMPurify.sanitize(input, {RETURN_DOM_FRAGMENT: true})` plus Trusted Types enforcement represents the strongest available defense.

---

## Cross-References

- **XSS Taxonomy**: See [`xss.md`](../01-injection/xss.md) §7 (Markup Parser Differential Context) for mXSS in the broader XSS classification structure
- **Universal XSS**: See [`universal-xss.md`](../05-client-side/universal-xss.md) for browser-level parsing vulnerabilities that share the namespace confusion mechanism
- **DOM Clobbering**: See [`dom-clobbering.md`](../05-client-side/dom-clobbering.md) for DOM clobbering gadgets that can be combined with mXSS for exploitation chains
- **Prototype Pollution**: See [`prototype-pollution.md`](../01-injection/prototype-pollution.md) for prototype pollution vectors that can disable sanitizer protections (CVE-2024-45801)
- **Browser Security Model**: See [`browser-security-model.md`](../05-client-side/browser-security-model.md) for the parsing pipeline that mXSS exploits
- **WAF Bypass**: See [`waf-bypass.md`](../08-infrastructure/waf-bypass.md) for WAF-level evasion that can complement mXSS sanitizer bypass

---

## References

- SonarSource. "mXSS: The Vulnerability Hiding in Your Code." https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/
- SonarSource. "mXSS Cheatsheet — Explained." https://sonarsource.github.io/mxss-cheatsheet/explained/
- SonarSource. "mXSS Cheatsheet — Payload Examples." https://sonarsource.github.io/mxss-cheatsheet/examples/
- SonarSource. "Code Vulnerabilities Put Proton Mails at Risk." https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/
- Securitum Research. "Write-up of DOMPurify 2.0.0 bypass using mutation XSS." https://research.securitum.com/dompurify-bypass-using-mxss/
- Securitum Research. "Mutation XSS via namespace confusion — DOMPurify < 2.0.17 bypass." https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
- PortSwigger Research. "Bypassing DOMPurify again with mutation XSS." https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- PortSwigger Research (Gareth Heyes). "Bypassing Firefox's HTML Sanitizer API." https://portswigger.net/research/bypassing-firefoxs-html-sanitizer-api
- Flatt Security Research. "Bypassing DOMPurify with good old XML." https://flatt.tech/research/posts/bypassing-dompurify-with-good-old-xml/
- kevin mizu. "Exploring the DOMPurify library: Bypasses and Fixes." https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
- kevin mizu. "Playing with DOMPurify's custom elements handling." https://mizu.re/post/playing-with-dompurify-ce-handling
- s1r1us. "MXSS Evolution and Timeline: A primer to MXSS." https://s1r1us.ninja/posts/mxss-101/
- Jorian Woltjer. "Mutation XSS: Explained, CVE and Challenge." https://jorianwoltjer.com/blog/p/hacking/mutation-xss
- Daniel Santos. "From SVG and back, yet another mutation XSS via namespace confusion for DOMPurify 2.2.2 bypass." https://vovohelo.medium.com/from-svg-and-back-yet-another-mutation-xss-via-namespace-confusion-for-dompurify-2-2-2-bypass-5d9ae8b1878f
- Huli (aszx87410). "Beyond XSS — Bypassing Your Defense: Mutation XSS." https://aszx87410.github.io/beyond-xss/en/ch2/mutation-xss/
- Huli (aszx87410). "Latest XSS Defense: Trusted Types and Built-in Sanitizer API." https://aszx87410.github.io/beyond-xss/en/ch2/trust-types/
- Bishop Fox. "LEXSS: Bypassing Lexical Parsing Security Controls." https://bishopfox.com/blog/lexss-bypassing-lexical-parsing-security-controls
- Insomnihack 2024. "Beating the Sanitizer: Why you should add mXSS to your Toolbox." https://insomnihack.ch/talks/beating-the-sanitizer-why-you-should-add-mxss-to-your-toolbox/
- Cure53. "mXSS Attacks: Attacking well-secured Web-Applications." https://cure53.de/fp170.pdf
- Frederik Braun. "Why the Sanitizer API is just." https://frederikbraun.de/why-sethtml.html
- WICG. "Sanitizer API — Rethink how we make sanitizeToString an mXSS-safe method." https://github.com/WICG/sanitizer-api/issues/37
- WHATWG. "HTML Standard — Dynamic markup insertion." https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html
- WHATWG. "HTML Standard — Parsing." https://html.spec.whatwg.org/multipage/parsing.html
- W3C. "DOM Parsing and Serialization." https://w3c.github.io/DOM-Parsing/
- David Klein, Martin Johns — *Parse Me, Baby, One More Time: Bypassing HTML Sanitizer via Parsing Differentials* (IEEE S&P 2024). 11 sanitizers × 5 languages; 5 parsing issues (PI), 2 serialization issues (SI); 16 bypasses; 19,843 coercion payloads. https://www.ias.cs.tu-bs.de/publications/parsing_differentials.pdf
- CVE-2024-47875. "DOMPurify nesting-based mXSS." https://github.com/advisories/GHSA-gx9m-whjm-85jf
- CVE-2025-26791. "DOMPurify incorrect template literal regex." https://github.com/advisories/GHSA-vhxf-7vqr-mrjg
- CVE-2024-52595. "lxml_html_clean namespace confusion bypass." https://www.miggo.io/vulnerability-database/cve/GHSA-mm7x-qfjj-5g2c
- CVE-2020-6802. "Bleach mutation XSS in noscript handling." https://bugzilla.mozilla.org/show_bug.cgi?id=1615315
- CVE-2020-6816. "Bleach mutation XSS with math/SVG and RCDATA tags." https://bugzilla.mozilla.org/show_bug.cgi?id=1621692
- msrkp. "Awesome MXSS — Curated mXSS resource collection." https://github.com/msrkp/MXSS

---

*This document was created for defensive security research and vulnerability understanding purposes.*
