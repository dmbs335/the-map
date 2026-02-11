# ZIP / Archive Vulnerability Mutation Taxonomy

A comprehensive, generalized classification of all known mutation and variation types across the ZIP (and related archive) vulnerability surface. This document organizes the entire attack landscape under structural criteria — what is mutated, what discrepancy it creates, and where it is weaponized — rather than by individual paper or source.

---

## Classification Structure

This taxonomy is organized along three orthogonal axes:

**Axis 1 — Mutation Target (Primary Structure):** The structural component of the ZIP file or extraction process being manipulated. This axis defines the eight top-level categories (§1–§8) and represents *what* the attacker modifies.

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the mismatch, bypass, or failure the mutation creates between two or more components. Every technique in §1–§8 maps to one or more of these discrepancy types:

| Discrepancy Type | Description |
|---|---|
| **Path Validation Bypass** | The extraction target path escapes the intended destination directory |
| **Parser Differential** | Two or more ZIP parsers interpret the same archive differently, seeing different filenames, file counts, or content |
| **Resource Exhaustion** | Decompression consumes disproportionate CPU, memory, or disk relative to archive size |
| **Security Metadata Evasion** | OS-level or application-level security markers (MotW, signatures, ADS) are stripped or not propagated |
| **Cryptographic Weakness** | The encryption layer is broken through known-plaintext, brute-force, or structural attacks |
| **Format Ambiguity** | The archive is simultaneously valid as multiple file formats, confusing tools that dispatch on format |

**Axis 3 — Attack Scenario (Mapping):** The real-world exploitation context is detailed in the Attack Scenario Mapping table at the end of the document.

### ZIP Format Fundamentals

A ZIP archive has a dual-index structure that is the root cause of most parser differentials:

1. **Local File Headers (LFH)** — precede each file's compressed data in the byte stream
2. **Central Directory (CD)** — an index at the end of the archive, listing all files with metadata
3. **End of Central Directory Record (EOCD)** — locates the Central Directory

The specification allows redundant and sometimes contradictory metadata between LFH and CD entries. Different parsers may prefer different sources of truth (LFH-first vs CD-first), creating a fundamental ambiguity that pervades the entire vulnerability surface.

---

## §1. File Path Manipulation

Attacks that modify the stored filename or path within archive entries to write files outside the intended extraction directory.

### §1-1. Classic Path Traversal (Zip Slip)

The most widespread archive vulnerability class. The attacker stores relative path traversal sequences in the filename field of archive entries. During extraction, if the library naively concatenates the entry name with the destination directory, the resulting path escapes the intended boundary.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Basic `../` traversal** | Entry name contains `../../evil.sh`; concatenation with `/tmp/extract/` yields `/tmp/evil.sh` | Extraction library does not canonicalize or validate the resolved path |
| **Absolute path injection** | Entry name is an absolute path like `/etc/cron.d/backdoor` | Library does not strip leading `/` or reject absolute paths |
| **Backslash variant** | Uses `..\..\` on Windows systems where `\` is a valid path separator | Library only checks for `/` as separator, missing `\` |
| **Mixed separator** | Combines `/` and `\` (e.g., `..\/..\/`) to confuse platform-specific validation | Cross-platform libraries that normalize inconsistently |
| **Null byte injection** | Inserts `%00` or literal null bytes in path to truncate validation while preserving traversal | Languages/APIs where null terminates strings differently (C vs Java) |
| **Double-encoding** | `%252e%252e%252f` decodes to `../` after double URL-decoding | Libraries that URL-decode filenames during extraction |
| **Overlong UTF-8** | Encodes `.` and `/` using multi-byte overlong UTF-8 sequences (e.g., `0xC0 0xAE` for `.`) | Decoders that accept non-shortest-form encodings |
| **Unicode normalization** | Uses Unicode characters that normalize to `.` or `/` (e.g., fullwidth `/` U+FF0F) | Systems that perform Unicode normalization after path validation |

**Affected formats:** ZIP, TAR, JAR, WAR, APK, RAR, 7z, CPIO — the vulnerability is format-agnostic and depends entirely on the extraction library's path handling.

### §1-2. Filename Encoding Confusion

The ZIP specification originally mandated CP437 encoding for filenames, with UTF-8 support added via the General Purpose Bit Flag (bit 11). This dual-encoding creates ambiguity.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CP437/UTF-8 mismatch** | Archive claims CP437 but contains UTF-8 bytes; or claims UTF-8 but contains CP437 | Parser does not verify encoding flag consistency |
| **Shift-JIS / EUC-KR injection** | Non-standard encodings are used (common in CJK locales), where multi-byte sequences contain `0x2F` (`/`) as a trail byte | Parser does not account for multi-byte encoding when scanning for path separators |
| **Homoglyph filenames** | Uses Cyrillic or other script characters visually identical to Latin (е vs e, а vs a) to mimic trusted filenames | Used in social engineering combined with MotW bypass (§5-1) |

### §1-3. Normalization Differential

Path normalization differences between the validation check and the actual filesystem operation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Check-vs-use normalization** | Validation uses one normalization form (e.g., `isContained()` check), but `fopen()` resolves the path differently | Common in Swift/iOS where Foundation and POSIX APIs normalize differently |
| **Case-folding traversal** | On case-insensitive filesystems, `..%c0%afETc/passwd` may bypass case-sensitive validation but resolve correctly | macOS HFS+ / Windows NTFS case-insensitivity |
| **Dot-stripping** | Windows strips trailing dots and spaces from filenames (`evil.exe.` → `evil.exe`) | Validation sees the dot-suffixed name as safe, but OS strips it |
| **Windows reserved names** | Entries named `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` trigger special OS behavior | Can cause DoS or unexpected file placement on Windows |

---

## §2. Symbolic Link Exploitation

Attacks that abuse symlink entries within archives to redirect file writes or reads to arbitrary locations.

### §2-1. Symlink Path Traversal

A two-phase attack: (1) extract a symlink entry that points outside the destination directory, then (2) extract a regular file entry whose path resolves through the symlink to an attacker-controlled location.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Relative symlink escape** | Symlink entry targets `../../etc/` ; subsequent file `symlink_name/crontab` writes to `/etc/crontab` | Library does not validate symlink targets or does not check resolved paths after symlink resolution |
| **Absolute symlink** | Symlink targets an absolute path like `/etc/` directly | Library creates symlinks without restricting target to extraction directory |
| **Chained symlinks** | Multiple symlink entries, each one level deeper, that together traverse to an arbitrary location | Library validates each symlink individually but not the composed chain |
| **Cross-platform symlink conversion** | Linux-style symlinks in ZIP entries are converted to Windows junction points or NTFS symlinks during extraction, without revalidating the target | 7-Zip on Windows (CVE-2025-11001, CVE-2025-11002, CVE-2025-55188) |

### §2-2. Symlink Read Primitives

Rather than writing files, symlinks can be used to *read* files by creating a symlink to a sensitive file, then re-archiving the extraction directory.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sensitive file exfiltration** | Symlink points to `/etc/shadow` or cloud credentials; a backup or re-archive operation follows the symlink | Application re-archives the extraction directory without dereferencing check |
| **Container escape via symlink** | In containerized environments, symlink targets host-mounted paths (e.g., `/proc/1/root/...`) | Volume mounts expose host filesystem to symlink traversal |

---

## §3. Archive Structure Manipulation

Attacks that exploit the dual-index nature of the ZIP format (Local File Headers vs Central Directory) and structural metadata ambiguities.

### §3-1. Local Header / Central Directory Inconsistency

The ZIP format stores metadata in both the Local File Header (LFH) and the Central Directory Header (CDH). When these disagree, different parsers may interpret the archive differently.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Filename mismatch** | LFH says `benign.txt`, CDH says `malicious.exe`; parser reads from LFH while display uses CDH (or vice versa) | Parser and UI/scanner use different header sources (CVE-2023-39137) |
| **Size mismatch** | Declared compressed/uncompressed sizes differ between LFH and CDH; one parser uses LFH sizes, another uses CDH | Enables zip bomb detection bypass or scanner confusion |
| **Compression method mismatch** | LFH declares STORED (0), CDH declares DEFLATE (8) | Parser may decompress or not depending on which header it trusts |
| **CRC-32 mismatch** | CRC values differ; strict parsers reject the file while lenient parsers process it | Security scanner crashes/rejects while target application accepts (CVE-2025-1944) |
| **Extra field divergence** | Different extra field data in LFH vs CDH; encryption flags, ZIP64 indicators, or timestamps disagree | Parser uses wrong extra field to interpret subsequent structure |

### §3-2. Central Directory Positioning

The EOCD record locates the Central Directory, but its position and offsets can be manipulated.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Prepended data (prefix injection)** | Arbitrary bytes prepended before the first LFH; CD offsets still valid from start of file | Some parsers calculate CD offset from file start, others from first LFH signature — see Janus (CVE-2017-13156) where DEX + APK coexist |
| **Appended data (suffix injection)** | Data appended after EOCD; some parsers search for EOCD from end-of-file, ignoring trailing garbage | Polyglot construction (§6) often uses this technique |
| **Multiple EOCD records** | Archive contains two or more EOCD signatures; parsers pick different ones | Each EOCD points to a different CD, showing entirely different file sets |
| **ZIP64 EOCD offset manipulation** | ZIP64 EOCD locator present but regular EOCD fields not set to 0xFFFFFFFF as required; some parsers ignore ZIP64, others prefer it | Office applications (Microsoft Office, LibreOffice) ignore ZIP64 EOCD and use the regular EOCD, seeing different files than ZIP64-aware parsers |
| **CD comment field abuse** | The EOCD `comment` field (up to 65535 bytes) can contain arbitrary data including fake LFH/CDH signatures | Parsers scanning for signatures may find fake entries within the comment |

### §3-3. Archive Concatenation

Multiple valid ZIP archives are concatenated into a single file, each with its own CD and EOCD.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dual-archive evasion** | First archive contains benign files, second contains malware; security tools read the first CD while extraction tools read the last CD | 7-Zip shows first archive only; WinRAR shows second; Windows Explorer shows second |
| **Triple-layer nesting** | Benign outer → benign inner → malicious deepest; progressive extraction reveals different content at each layer | Recursive unpackers may stop at first or second layer |
| **Comment-separated concatenation** | Archives separated by data disguised as EOCD comments, making the boundary ambiguous | Parsing heuristics vary on where one archive ends and another begins |

### §3-4. Entry Count and Ordering

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Duplicate filenames** | Multiple entries with the same filename; some parsers keep the first, others keep the last | The "safe" file is overwritten by the "malicious" duplicate (Android Master Key bug) |
| **Entry count mismatch** | EOCD declares N entries but CD contains M > N; parsers may process only N or all M | Extra entries are invisible to scanners that trust the count |
| **Zero-entry archive** | EOCD declares zero entries, but LFH entries exist; data descriptor-based parsers still process them | Scanners skip "empty" archives |

---

## §4. Compression and Decompression Attacks

Attacks that exploit the compression/decompression layer to cause resource exhaustion or bypass size-based security checks.

### §4-1. Non-Recursive Zip Bombs (Overlap Bombs)

Achieve extreme compression ratios in a single decompression pass by making multiple CD entries point to the same underlying compressed data.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Overlapping file entries** | N central directory entries reference the same DEFLATE kernel; decompressor outputs N copies | 42 KB → 5.5 GB; 10 MB → 281 TB; 46 MB → 4.5 PB (ZIP64) |
| **DEFLATE kernel with quoted headers** | Non-compressed DEFLATE blocks embed subsequent LFH headers as literal data, creating a continuous stream that is both valid compressed data and valid ZIP structure | Requires careful construction of 5-byte non-compressed block headers |
| **Bzip2/LZMA kernel variant** | Same overlapping technique but using bzip2 or LZMA instead of DEFLATE, which may evade DEFLATE-specific detection | Parsers that support multiple compression methods |

### §4-2. Recursive Zip Bombs

Traditional nested archives that require recursive extraction to fully expand.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nested archive bomb** | ZIP within ZIP within ZIP... each layer expands to multiple archives at the next level | Classic 42.zip: 42 KB → 4.5 PB across 5 layers of nesting |
| **Cross-format nesting** | ZIP → TAR.GZ → ZIP → RAR chain; each format change may reset extraction depth counters | Recursive unpackers that track depth per-format rather than globally |
| **Zip quine** | Self-reproducing archive: the archive contains a copy of itself, creating infinite recursion on recursive extraction | `droste.zip` — a ZIP file that contains exactly itself |

### §4-3. Compression Ratio Amplification

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Repeated-byte kernel** | DEFLATE stream encoding a single byte repeated billions of times; trivial to compress, expensive to decompress | No overlap needed; pure DEFLATE exploitation |
| **Data descriptor size lie** | LFH declares size = 0, actual size is in data descriptor after compressed data; decompressor allocates based on declared size, then runs out of memory on actual data | Parsers that pre-allocate based on declared uncompressed size |
| **Uncompressed size overflow** | Declared uncompressed size is `0xFFFFFFFF` (4 GB max for ZIP32); actual decompressed data exceeds this | Integer overflow in size tracking can wrap to small allocation |

---

## §5. Security Metadata Manipulation

Attacks that strip, bypass, or prevent propagation of OS-level or application-level security markers.

### §5-1. Mark-of-the-Web (MotW) Bypass

Windows uses Zone.Identifier alternate data streams to mark files downloaded from the internet. Archive extractors are expected to propagate this marker to extracted files.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nested archive MotW non-propagation** | Outer archive has MotW, but files extracted from a nested (inner) archive do not receive MotW | 7-Zip before 24.09 (CVE-2025-0411); exploited in the wild with SmokeLoader malware against Ukrainian organizations |
| **Homoglyph inner archive naming** | Inner archive uses Cyrillic homoglyphs in filename (e.g., `Доcument.docx` with mixed scripts) to appear as a document while being an archive | Social engineering combined with MotW non-propagation |
| **Format-specific MotW gaps** | Certain archive formats (e.g., ISO, VHD, IMG) do not propagate MotW by design on some Windows versions | Attackers wrap malicious ZIPs in ISO containers to strip MotW |

### §5-2. Alternate Data Stream (ADS) Exploitation

NTFS Alternate Data Streams can be embedded within or alongside archive entries.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ADS path traversal** | Archive entry uses ADS syntax (`filename:stream_name:$DATA`) combined with `../` to write payload to arbitrary location via ADS | WinRAR before 7.13 (CVE-2025-8088): payload hidden in ADS of decoy file, written to Startup folder |
| **ADS-embedded payload** | Malicious code stored in ADS of a benign-looking file within the archive; most security scanners only scan the default data stream | Antivirus tools that do not enumerate or scan ADS |
| **ADS with space-in-path** | Spaces in relative paths combined with ADS notation circumvent path filters | WinRAR before 7.12 (CVE-2025-6218) |

### §5-3. Signature and Integrity Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **APK signature scheme bypass** | APK is a ZIP; prepending DEX bytecode before the ZIP portion creates a DEX+APK polyglot that passes APK signature verification (which only verifies ZIP entries) but is also valid as a DEX file | Android Janus vulnerability (CVE-2017-13156); APK Signature Scheme v1 |
| **JAR signature tampering** | Modifying ZIP structure (CD offsets, entry ordering) without altering the signed content within individual entries; signature verification passes but different files are loaded | Spring Boot signed JAR bypass via ZIP64 EOCD manipulation |
| **Tampered APK headers (BadPack)** | Modifying ZIP header values in APK files to prevent analysis tools from parsing them, while Android's runtime parser still loads them correctly | Nearly 9,200 BadPack samples detected between June 2023 and June 2024 |

---

## §6. File Format Boundary Exploitation (Polyglots)

Attacks that create files simultaneously valid as ZIP archives and another format, exploiting the fact that ZIP's structure (CD at end, arbitrary prefix allowed) makes it inherently polyglot-friendly.

### §6-1. ZIP + Executable Polyglots

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DEX + APK (Janus)** | DEX header at file start, ZIP/APK structure at end; Android loads as DEX if invoked as DEX, as APK if invoked as APK | Android Dalvik/ART runtime (CVE-2017-13156) |
| **EXE + ZIP (SFX exploitation)** | Self-extracting archive structure where the PE header is followed by ZIP data; file is both a valid executable and a valid archive | Self-extracting archives are inherently polyglots; malware can abuse this duality |
| **ELF + ZIP** | ELF binary prepended to ZIP; Linux executes the ELF portion, archive tools see the ZIP portion | Applications that accept "ZIP files" without verifying that ZIP structure starts at offset 0 |

### §6-2. ZIP + Document Polyglots

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDF + ZIP** | PDF header and object stream in prefix, ZIP data appended; email scanners see PDF, extractors see ZIP | Used in Sosano backdoor campaign (2024-2025) |
| **BMP + ZIP (image polyglot)** | BMP image data followed by ZIP content; image viewers render the image, archive tools extract the ZIP | Used in malware dropper chains: DOC macro → PNG → BMP → ZIP conversion |
| **HTML + ZIP** | HTML content in prefix with ZIP appended; browsers render HTML, archive tools extract ZIP | Potential XSS vector when ZIP files are served with text/html content type |
| **Office document + ZIP** | Since DOCX/XLSX/PPTX are themselves ZIP archives, a carefully constructed file can be valid as two different Office document types simultaneously | Parser confusion between intended and injected content |

### §6-3. ZIP + Archive Polyglots

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RAR + ZIP** | File is valid as both RAR and ZIP; different extraction tools see different content | Content-inspection systems that identify format by magic bytes may choose the wrong parser |
| **GZ + ZIP** | GZIP header at start with ZIP appended; tools dispatching on header magic see GZIP, tools scanning for EOCD from end see ZIP | Differential content based on parser selection |

---

## §7. Parser Implementation Differentials

Attacks that exploit the inconsistent implementation of the ZIP specification across different parsers, frameworks, and languages. Research on 50 ZIP parsers across 19 languages identified 14 distinct ambiguity types in three categories.

### §7-1. Redundant Metadata Ambiguities

When the same piece of information exists in multiple places within the ZIP structure, parsers may prefer different sources.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **LFH vs CDH filename preference** | Parser A uses LFH filename, Parser B uses CDH filename; attacker places benign name in one and malicious name in the other | Security scanner and extraction tool use different header preferences |
| **LFH vs CDH size preference** | Compressed/uncompressed sizes differ between LFH and CDH; allocators and decompressors make different decisions | Can cause buffer overflows or underflows in size-trusting parsers |
| **Data descriptor vs header sizes** | When bit 3 of general purpose flag is set, sizes should be in data descriptor, but some parsers still use LFH values | Size-checking security tools may use the wrong source |
| **Extra field interpretation** | Extended timestamp, NTFS attributes, Unicode path — parsers vary in which extra fields they support and prioritize | Unicode Path Extra Field can override the main filename differently across parsers |

### §7-2. File Path Processing Ambiguities

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path separator handling** | Some parsers treat `\` as a directory separator, others treat it as a literal character | Windows vs Unix extraction of the same archive yields different directory structures |
| **Trailing slash semantics** | Entry name ending in `/` is a directory marker; some parsers create the directory, others create a zero-byte file | Affects directory creation and subsequent file placement |
| **Dot-dot resolution timing** | Some parsers resolve `../` before extraction, others after; some normalize the path, others reject it | The same traversal payload works on some parsers but not others |
| **Empty filename handling** | Entries with zero-length filenames; some parsers skip them, others create files with generated names, others crash | DoS or undefined behavior |

### §7-3. ZIP Structure Positioning Ambiguities

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **EOCD search direction** | Most parsers search backwards from end-of-file for EOCD; some search forward | In concatenated archives, search direction determines which CD is found |
| **Offset base calculation** | Offsets to CD calculated from file start vs from first LFH signature; difference matters when data is prepended | Go's archive/zip vs Python's zipfile resolve differently |
| **Overlapping entry handling** | When file data regions overlap, some parsers extract all entries (outputting duplicated data), others detect and reject | Zip bomb detection relies on overlap detection; some parsers miss it |
| **Garbage tolerance** | Some parsers skip non-ZIP data between entries, others abort on unexpected bytes | Affects polyglot viability and concatenation attacks |
| **ZIP64 fallback behavior** | When ZIP64 records exist but regular EOCD is not set to `0xFFFFFFFF`, parsers vary on whether to prefer ZIP64 or regular EOCD | Office applications ignore ZIP64 EOCD while other tools prefer it, showing different files |

### §7-4. Real-World Exploitation of Parser Differentials

These ambiguities have been weaponized in several concrete attack scenarios:

| Scenario | Technique | Impact |
|---|---|---|
| **Secure email gateway bypass** | Craft ZIP where scanner sees benign files via CDH while extraction yields malware via LFH | Bypassed Gmail, Coremail, Zoho (bounties awarded) |
| **Office document spoofing** | ZIP64 EOCD manipulation shows one document to signature verifier, another to reader | Content forgery in signed documents |
| **VS Code extension impersonation** | Parser differential causes marketplace scanner to see legitimate extension while user installs malicious code | Supply chain attack on developer tools |
| **Spring Boot signed JAR tampering** | Nested JAR signature verification uses different CD than classloader | Signed code integrity bypass |
| **ML model supply chain** | CVE-2025-1944: CRC mismatch crashes picklescan but PyTorch loads model anyway | Backdoored ML models bypass safety scanners |

---

## §8. Encryption Layer Attacks

Attacks against the cryptographic protection of encrypted ZIP archives.

### §8-1. ZipCrypto (Legacy Encryption) Weaknesses

The original PKWARE encryption scheme (ZipCrypto) is fundamentally broken but remains the default in many tools.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Known-plaintext attack (Biham-Kocher)** | With 12+ bytes of known plaintext, the internal state of the PKZIP stream cipher is recoverable; all entries encrypted with the same password are then decryptable | Attacker knows partial file content (e.g., file headers like PK signatures, XML declarations, or standard file structures) |
| **Reduced known-plaintext** | Optimized attacks requiring fewer known bytes by exploiting the CRC pre-check mechanism | Even small known-plaintext fragments (8 bytes) can be sufficient with modern tools |
| **Password recovery from internal keys** | Once internal keys are recovered, password itself can be brute-forced with complexity n^(l-6) | Practical for short passwords |
| **Content replacement without password** | Using recovered internal keys, the attacker replaces encrypted content without ever knowing the password | Tool: bkcrack enables both decryption and re-encryption |

### §8-2. AES-Encrypted ZIP Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Weak password brute-force** | AES-256 encrypted ZIPs with weak passwords remain vulnerable to dictionary/mask attacks | GPU-accelerated cracking tools achieve high throughput |
| **No authentication (pre-WinZip AE-2)** | Original WinZip AE-1 format allows tampering with encrypted data without detection (no HMAC on file data) | Can corrupt or manipulate encrypted content |
| **Password verification bypass** | The 2-byte password verification value can be brute-forced independently (65536 attempts) to quickly filter candidate passwords | Reduces computational cost of brute-force attacks |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Example |
|---|---|---|---|
| **Arbitrary File Write → RCE** | Any system extracting user-supplied archives | §1 + §2 | Zip Slip writes webshell to web root; symlink writes crontab |
| **Denial of Service** | Servers, email gateways, CI/CD pipelines processing uploads | §4 + §3-4 | Zip bomb exhausts memory/disk; entry count crash |
| **Security Scanner Bypass** | Email gateways, antivirus, WAF, EDR | §3-3 + §6 + §7 | Concatenated ZIP shows benign to scanner, malicious to extractor |
| **Signature/Integrity Bypass** | Android APK, signed JARs, code signing | §5-3 + §3-2 | Janus DEX+APK polyglot; Spring Boot signed JAR tampering |
| **MotW / SmartScreen Bypass** | Windows desktop, endpoints, phishing campaigns | §5-1 + §5-2 | Nested archive strips MotW; ADS writes to Startup folder |
| **Supply Chain Attack** | Package managers, ML model hubs, extension marketplaces | §7-4 + §5-3 | Picklescan bypass; VS Code extension impersonation |
| **Malware Delivery / Evasion** | Phishing, email attachments | §6 + §3-3 + §5-1 | PDF+ZIP polyglot; concatenated archive; MotW bypass |
| **Container / Sandbox Escape** | Docker, Kubernetes, cloud environments | §2-2 + §1-1 | Symlink targets host mount; path traversal escapes chroot |
| **Data Exfiltration** | Backup systems, file sync services | §2-2 | Symlink to sensitive file included in backup archive |
| **Cryptographic Content Access** | Encrypted archives in forensics, data theft | §8 | Known-plaintext attack on ZipCrypto; password brute-force |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 (cross-platform symlink) | CVE-2025-11001 (7-Zip < 25.00) | Path traversal → RCE via symlink on Windows. Actively exploited in the wild. |
| §2-1 (cross-platform symlink) | CVE-2025-11002 (7-Zip < 25.00) | Secondary symlink traversal vector in 7-Zip. |
| §2-1 (symlink → arbitrary file write) | CVE-2025-55188 (7-Zip < 25.01) | Arbitrary file write on extraction via unsafe symlink creation. |
| §5-1 (nested archive MotW bypass) | CVE-2025-0411 (7-Zip < 24.09) | MotW bypass → SmokeLoader malware delivery. Ukrainian organizations targeted. CVSS 7.0. |
| §5-2 (ADS path traversal) | CVE-2025-8088 (WinRAR < 7.13) | Zero-day ADS + `../` traversal → Startup folder persistence. Exploited by RomCom, APT44, Turla, PRC actors. |
| §5-2 (ADS space-in-path) | CVE-2025-6218 (WinRAR < 7.12) | ADS with spaces in relative path → RCE. CVSS 7.8. |
| §1-1 (classic path traversal) | CVE-2025-3445 (Go mholt/archiver) | Zip Slip in popular Go archiver library via symlink + path traversal. |
| §1-1 (classic path traversal) | CVE-2025-65346 (unzip functionality) | Path traversal via unsanitized destination paths in ZIP entries. |
| §1-1 (path traversal) | CVE-2025-12060 (Keras) | Directory traversal in ML framework archive extraction. |
| §3-1 (CRC mismatch → scanner crash) | CVE-2025-1944 (picklescan < 0.0.23) | ZIP header manipulation crashes scanner; PyTorch still loads malicious model. |
| §4-3 (quoted-overlap bomb) | CVE-2024-0450 (CPython zipfile) | Quoted-overlap zip-bomb in Python's zipfile module; all Python versions affected. |
| §4-1 (decompression DoS) | CVE-2025-69223 (AIOHTTP ≤ 3.13.2) | Zip bomb exhausts host memory via HTTP/gRPC. |
| §4-1 (decompression DoS) | CVE-2025-63914 (Cinnamon/kotaemon) | No decompression limits → DoS via zip bomb. |
| §1-1 (Zip Slip) | CVE-2024-21518 (OpenCart) | Marketplace installer Zip Slip → arbitrary file write via admin panel. |
| §3-1 (filename spoofing) | CVE-2023-39137 (Dart archive) | LFH/CDH filename mismatch → filename spoofing in mobile apps. |
| §2-1 (symlink traversal) | CVE-2023-39139 (Dart archive) | Symlink targets not validated → arbitrary file read/write. |
| §1-3 (normalization differential) | CVE-2023-39138 (Swift ZIPFoundation) | `isContained()` bypass via path normalization difference. |
| §5-3 (APK signature bypass) | CVE-2017-13156 (Android Janus) | DEX+APK polyglot bypasses APK v1 signature verification. |
| §3-4 (duplicate filenames) | Android Master Key Bug (2013) | Duplicate ZIP entries; first passes verification, second is loaded. |
| §7-4 (parser differential) | Gmail/Coremail/Zoho bounties (2025) | ZIP parser differential bypasses secure email gateway scanning. |
| §7-4 (parser differential) | Spring Boot CVE (2025) | Signed JAR tampering via CD offset manipulation. |
| §7-4 (parser differential) | LibreOffice CVE (2025) | ZIP64 EOCD manipulation causes document content spoofing. |
| §6-1 (polyglot) | CVE-2025-58440 (Laravel FileManager) | Polyglot file + null byte injection → RCE. |
| §5-3 (tampered headers) | BadPack APK malware (2023–2024) | ~9,200 samples with tampered ZIP headers to prevent analysis tool parsing. |
| §7-4 (parser differential) | CVE-2025-62156 (Argo Workflow) | Zip Slip vulnerability in Argo Workflow's archive handling. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **ZipDiff** (Research fuzzer) | 50 ZIP parsers across 19 languages | Grammar-based differential fuzzing; generates ZIP mutations and compares parser outputs to find semantic gaps |
| **FormatFuzzer** (Generator-based fuzzer) | ZIP + other binary formats (MP4, etc.) | Compiles binary templates into C++ parser/mutator/generators for format-specific fuzzing |
| **VERTFuzz** (Version-aware fuzzer) | Complex file parsers including ZIP | Transformer-driven mutation targeting version-specific parser behaviors |
| **bkcrack** (Crypto tool) | ZipCrypto-encrypted archives | Known-plaintext attack implementation; recovers internal keys with 12+ bytes of known plaintext |
| **GPUZipCracker** (Crypto tool) | AES/ZipCrypto-encrypted archives | GPU-accelerated password cracking for encrypted ZIP archives |
| **Snyk Zip Slip scanner** (Vulnerability scanner) | Source code across multiple languages | Static analysis detecting unsafe archive extraction patterns |
| **PolyConv** (Detector) | Polyglot files | Detects files valid as multiple formats by analyzing structural markers |
| **picklescan** (ML security) | PyTorch model archives (ZIP-based) | Scans for malicious pickle payloads in ML model files; vulnerable to ZIP manipulation itself |
| **zipdetails** (Analysis) | ZIP structure inspection | Perl tool that dumps complete ZIP internal structure for manual analysis |

---

## Summary: Core Principles

**The fundamental property** that makes the entire ZIP vulnerability surface possible is **structural redundancy combined with end-anchored indexing**. The ZIP format stores metadata in multiple locations (Local File Headers, Central Directory, EOCD, Data Descriptors, Extra Fields), allows arbitrary data to exist between and around these structures, and anchors its primary index (the Central Directory) at the end of the file rather than the beginning. This design, originally optimized for append-friendly operation on floppy disks, creates an inherently ambiguous format where different parsers can legitimately interpret the same byte sequence as different archives.

**Incremental patches fail** because the attack surface is not a collection of individual bugs but a consequence of specification-level ambiguity. Fixing one parser's handling of LFH/CDH inconsistency does not affect the 49 other parsers that handle it differently. Fixing symlink handling in 7-Zip 25.00 does not prevent the same vulnerability pattern from recurring in every new ZIP library written from scratch. The ZIP specification (APPNOTE.TXT) is descriptive rather than prescriptive — it documents what PKWARE's implementation does rather than mandating what all implementations must do, leaving vast room for interpretation.

**A structural solution** would require either (1) a strict, unambiguous archive format that eliminates all redundant metadata and mandates a single canonical parsing algorithm (effectively a new format, not ZIP), or (2) universal adoption of a "paranoid parsing" approach that rejects any archive containing inconsistencies between redundant fields — an approach that would break compatibility with a significant fraction of existing ZIP files in the wild. In practice, the most effective defense is defense-in-depth: validate extracted paths against the destination directory after full resolution, never follow symlinks during extraction, impose resource limits on decompression, propagate security metadata through all nesting levels, and use the same ZIP parser for scanning as for extraction to eliminate parser differentials.

---

## References

- USENIX Security '25: "My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers" — https://www.usenix.org/conference/usenixsecurity25/presentation/you
- WOOT '19: "A better zip bomb" — https://www.bamsoftware.com/hacks/zipbomb/
- Snyk Research: "Zip Slip Vulnerability" — https://security.snyk.io/research/zip-slip-vulnerability
- Ostorlab: "ZIP Exploitation: Critical Vulnerabilities Found in Popular Zip Libraries" — https://blog.ostorlab.co/zip-packages-exploitation.html
- Arxiv: "Where the Polyglots Are: How Polyglot Files Enable Cyber Attack Chains" — https://arxiv.org/html/2407.01529v1
- INRIA: "Decompression Quines and Anti-Viruses" — https://inria.hal.science/hal-01589192v2/document
- Trend Micro: "CVE-2025-0411: Ukrainian Organizations Targeted in Zero-Day Campaign" — https://www.trendmicro.com/en_us/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html
- Google Cloud Blog: "Diverse Threat Actors Exploiting Critical WinRAR Vulnerability CVE-2025-8088" — https://cloud.google.com/blog/topics/threat-intelligence/exploiting-critical-winrar-vulnerability
- ThreatLocker: "Analysis of 7-Zip vulnerabilities: CVE-2025-11001 and CVE-2025-11002" — https://www.threatlocker.com/blog/analysis-of-7-zip-vulnerabilities-cve-2025-11001-and-cve-2025-11002
- Perception Point: "Evasive ZIP Concatenation: Trojan Targets Windows Users" — https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/
- Sonatype: "Exposing 4 Critical Vulnerabilities in Python Picklescan" — https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities
- Biham & Kocher: "A known plaintext attack on the PKZIP stream cipher" — https://math.ucr.edu/~mike/zipattacks.pdf
- Palo Alto Unit 42: "Beware of BadPack: One Weird Trick Being Used Against Android Devices" — https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/
- CrowdStrike: "How to Prevent Zip File Exploitation" — https://www.crowdstrike.com/en-us/blog/how-to-prevent-zip-file-exploitation/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
