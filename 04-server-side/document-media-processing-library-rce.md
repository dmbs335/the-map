# Document & Media Processing Library RCE — Mutation/Variation Taxonomy

*Recurring code-execution attack surfaces in libraries that parse, render, convert, or transform documents, images, media, fonts, and structured file formats.*

---
## Classification Structure

Server-side processing of documents, images, fonts, and media files is ubiquitous — from thumbnail generation to format conversion, metadata extraction, document rendering, and content delivery. Each processing library implements complex parsers for binary formats, compression algorithms, scripting engines, and protocol handlers in memory-unsafe languages, creating a vast attack surface where malformed input triggers memory corruption, command injection, sandbox escape, or logic abuse. The critical insight is that the **file itself is the attack vector** — no injection point in a web form is needed, only the ability to upload or reference a file that will be processed.

This taxonomy organizes Document & Media Processing Library RCE vectors along three axes:

**Axis 1 — Processing Target (Primary, §1–§9):** The structural category of the processing library or engine being exploited. This axis structures the main body of the document.

**Axis 2 — Exploitation Primitive (Cross-cutting):** The fundamental mechanism by which code execution is achieved. These primitives recur across multiple processing target categories:

| Primitive | Description | Primary Sections |
|---|---|---|
| **Memory Corruption** | Heap overflow, use-after-free, integer overflow, stack buffer overflow, type confusion in native parsers | §1, §3, §4, §5, §8 |
| **Command/Code Injection** | Unsanitized input reaches shell `system()`, `eval()`, interpreter backtick, or expression language context | §2, §7, §8 |
| **Sandbox Escape** | Breaking out of an intended security boundary (PostScript `-dSAFER`, PDF JavaScript sandbox, Office macro restrictions) | §2, §5, §6 |
| **File Write → Execution** | Arbitrary file write primitive weaponized via webshell deployment, font cache poisoning, config overwrite, or cron/scheduled task injection | §2, §6, §9 |
| **Protocol/Scheme Abuse** | SSRF, local file read, or network interaction via URL scheme handlers, protocol delegates, or resource loading | §2, §3, §6, §9 |
| **Logic/Design Exploitation** | Turing-complete in-format computation, polyglot file confusion, format auto-detection bypass, implicit code execution by design | §2, §5, §6, §7 |
| **Deserialization/Entity Expansion** | XXE, DTD processing, object graph manipulation, unsafe unmarshaling during document parsing | §6, §8 |

**Axis 3 — Attack Scenario (Mapping):** The real-world deployment context in which the mutation becomes exploitable — server-side file upload processing, document conversion pipelines, thumbnail/preview generation, email attachment scanning, mobile zero-click, browser rendering, CI/CD build pipelines, and antivirus/security scanner processing.

---

## §1. Image Processing Library Memory Corruption

Image format parsers implement complex compression algorithms (Huffman coding, LZ77, arithmetic coding, wavelet transforms) in C/C++, making them fertile ground for memory corruption vulnerabilities. A single malformed image file — uploaded as a profile picture, embedded in a document, or fetched via URL — can trigger heap manipulation leading to arbitrary code execution.

### §1-1. Heap Buffer Overflow in Decompression

The most common class of image processing RCE. Compression decoders allocate output buffers based on header-declared dimensions or table sizes, then write decompressed data without adequate bounds checking.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Huffman table overflow** | Malformed lossless image files trigger out-of-bounds heap writes during Huffman table construction. A specially crafted `BuildHuffmanTable` call writes beyond allocated buffer boundaries | libwebp < 1.3.2 (CVE-2023-4863; NVD/CISA-ADP CVSS 8.8). Exposure requires a vulnerable bundled library and a reachable lossless-WebP decode path. CVE-2023-5129 was rejected as a duplicate |
| **Interlaced PNG 16-to-8 conversion overflow** | When processing 16-bit interlaced PNGs with 8-bit output format, `png_combine_row` writes combined row data beyond the allocated buffer due to miscalculated row sizes | libpng 1.6.0–1.6.50 (CVE-2025-65018); may enable arbitrary code execution in certain heap configurations |
| **JPEG2000 Ndecomp field overflow** | A specially crafted JPEG2000 file exploits the Ndecomp parameter handling to cause heap-based buffer overflow, leading to adjacent heap memory overwrite | NVIDIA nvJPEG2000 0.8.0 (TALOS-2024-2113, TALOS-2024-2108); GPU-accelerated image processing pipelines |
| **DDS format heap corruption** | Malformed DDS (DirectDraw Surface) images trigger heap buffer overflow during encoding when sufficiently large images (>64k) are processed with default compression settings | Pillow 11.2.0–11.3.0 |
| **VP8 encoding overflow** | Heap buffer overflow in VP8 encoding within libvpx allows crafted video frames to corrupt heap state during encoding operations | libvpx (CVE-2023-5217); affects Chromium, Firefox, video processing pipelines |
| **PNM frame decode overflow** | `pnm_decode_frame` function contains heap-based buffer overflow exploitable via crafted PNM image files | FFmpeg ≤ 7.0.1 (CVE-2024-7055) |

### §1-2. Integer Overflow Leading to Undersized Allocation

Integer overflows in dimension calculations or counter arithmetic cause the allocator to reserve a buffer smaller than what the decoder will write, converting a benign-looking arithmetic error into a precise heap corruption primitive.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JBIG2 symbol count overflow** | `numSyms` can be smaller than the size of one `JBIG2Segment` due to integer overflow, causing loop iterations beyond allocated buffer bounds — the foundational primitive of the FORCEDENTRY exploit | Apple CoreGraphics JBIG2 decoder (CVE-2021-30860); Poppler, Xpdf JBIG2 decoders (CVE-2022-38784) |
| **BMP encoder dimension overflow** | 32-bit integer overflow in ImageMagick's BMP encoder causes undersized heap allocation followed by oversized write when encoding images with extreme dimensions | ImageMagick on 32-bit builds (CVE-2025-57803, CVSS 7.5) |
| **Palette index overflow** | Heap buffer over-read in `png_do_quantize` triggered by malformed palette index values exceeding the allocated palette size | libpng 1.6.0–1.6.50 (CVE-2025-64505) |
| **TIFF StripByteCount overflow** | Integer overflow in TIFF strip/tile byte count fields causes undersized buffer allocation followed by oversized decompression write | libtiff (historical pattern — 63+ overflow CVEs, including CVE-2025-9900 write-what-where) |
| **Reference count overflow** | `std::atomic_int` used for reference counting overflows, triggering use-after-free when the counter wraps to zero prematurely | Poppler ≤ 25.06.0 (CVE-2025-52886); PDF rendering pipelines |

### §1-3. Use-After-Free in Object Lifecycle

Complex image formats contain cross-referenced objects (color profiles, palettes, metadata blocks) with non-trivial lifecycle management. When an object is freed but a reference persists, subsequent use of the dangling pointer enables controlled heap corruption.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDFium object UAF** | Use-after-free in Chrome's PDFium engine when processing crafted PDF files containing complex annotation objects or cross-referenced page resources | Chrome PDFium (CVE-2024-5846, CVE-2024-5847); browser-based PDF rendering |
| **Image profile UAF** | Color profile (ICC) objects freed during format conversion while still referenced by the output image structure | ImageMagick, GraphicsMagick profile handling |
| **Xz decompression UAF** | Use-after-free in Xz decompression module during archive/stream processing | ClamAV (fixed in 1.4.3/1.0.9); antivirus scanning of compressed content |

### §1-4. Pixel Flood and Resource Amplification

While not always direct RCE, resource amplification attacks exhaust memory to create heap instability, enable heap feng shui for subsequent exploitation, or cause denial-of-service that masks concurrent attacks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dimension bomb** | Image header declares massive dimensions (e.g., 65535×65535×4 channels = 16GB) with minimal compressed file size. Library allocates based on declared dimensions before validating | Any library allocating from header values without capping; "decompression bomb" |
| **Deeply nested structure recursion** | PDF or SVG documents with deeply nested structural elements cause stack consumption and crash via unbounded recursion | Poppler 24.06.1–25.04.0 (stack consumption via nested PDF metadata) |
| **FlateDecode/LZW stream bomb** | Heavily compressed PDF/image streams expand orders of magnitude during decompression, exhausting memory | PDF processing pipelines without decompression limits |

---

## §2. Image Processing Delegate & Scripting Exploitation

Several image processing frameworks achieve format coverage not through built-in parsers but through **delegation** — invoking external programs, scripting engines, or plugin architectures. This delegation creates command injection surfaces entirely separate from memory corruption.

### §2-1. ImageMagick Delegate Command Injection

ImageMagick processes complex formats by delegating to external programs via `system()` calls defined in `delegates.xml`. This architecture creates persistent command injection paths because filenames flow unsanitized into shell commands.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MVG/SVG delegate injection (ImageTragick)** | MVG/SVG files invoke delegates with filenames containing shell metacharacters: `fill 'url(https://x.com/img.jpg"\|id "-la)'`. The delegate system passes these through `system()` | ImageMagick with default `delegates.xml` and insufficient `policy.xml` (CVE-2016-3714) |
| **MSL pseudo-protocol file write** | MSL (Magick Scripting Language) files direct ImageMagick to read an image and write it to an arbitrary path with arbitrary extension: `msl:malicious.msl` → webshell deployment | MSL protocol not disabled in `policy.xml` |
| **`@` file read primitive** | `label:@/etc/passwd` or `text:@/etc/passwd` causes ImageMagick to read the specified file and render its content as text in the output image, enabling information disclosure | `@` file reading not restricted by policy |
| **Environment variable policy bypass** | AppImage-packaged ImageMagick loads `delegates.xml` from the current working directory if `MAGICK_CONFIGURE_PATH` contains empty path entries, allowing attacker-controlled delegate definitions | AppImage distribution with manipulable working directory |
| **Framework-level shell-out injection** | Web frameworks pass user-controlled filenames to ImageMagick CLI without sanitization: `convert "$(whoami).jpg" output.png` | CodeIgniter ImageManipulation handler (CVE-2025-54418, CVSS 9.8); any framework shelling out to `convert`/`magick` |
| **PDF password field shell injection** | When ImageMagick processes password-protected PDF files, the password is passed to the Ghostscript delegate via command-line arguments constructed through `delegates.xml`. A crafted password string containing shell metacharacters (e.g., `$(id)` or `` `id` ``) is interpolated unsanitized into the shell command, achieving command injection via the password parameter rather than the filename | ImageMagick processing password-protected PDFs with Ghostscript delegate; password supplied via user input or metadata |

### §2-2. Ghostscript PostScript Sandbox Escape

Ghostscript processes PostScript — a **Turing-complete programming language** — with a `-dSAFER` sandbox that restricts dangerous operations. Every sandbox bypass achieves full RCE because PostScript can natively execute system commands when restrictions are lifted. Ghostscript is invoked downstream by ImageMagick, LibreOffice, GIMP, Inkscape, CUPS, and numerous PDF processing pipelines, amplifying the blast radius.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Format string sandbox disable** | A format string vulnerability in the `uniprint` device allows modification of device argument strings after sandbox activation. By writing to the `path_control_active` flag in memory, the attacker disables `-dSAFER` entirely at runtime | Ghostscript ≤ 10.03.0 (CVE-2024-29510); actively exploited in the wild via EPS files disguised as JPEGs |
| **Pipe device shell execution** | PostScript `%pipe%` device executes shell commands: `(%pipe%id) (r) file` reads command output. Periodic sandbox bypass techniques re-enable access to this device | Ghostscript with incomplete pipe device restriction |
| **OCR device file read/write** | The tesseract OCR device can be abused to read arbitrary files from the filesystem and write output to attacker-controlled paths | Ghostscript ≤ 10.03.0 (CVE-2024-29511); OCR device enabled |
| **IJS server exploitation** | The IJS (InkJet Server) protocol allows Ghostscript to communicate with external processes. Crafted IJS URIs can trigger execution of attacker-specified binaries | IJS support enabled |
| **OutputFile path traversal** | Setting `-sOutputFile=/var/www/html/shell.php` with crafted PostScript content generates a PHP webshell as the "rendered output" | Ghostscript invoked with user-controlled output path |
| **Buffer overflow in device handling** | Multiple buffer overflow vulnerabilities in Ghostscript's device handling code enable memory corruption without requiring PostScript-level sandbox escape | Ghostscript (CVE-2024-29506 through CVE-2024-29509); multiple memory corruption paths |
| **Downstream library chaining** | Ghostscript is invoked by ImageMagick (via delegates), LibreOffice (for EPS rendering), GIMP, Inkscape, and CUPS. A Ghostscript sandbox escape through any of these chains becomes an RCE in the consuming application | Any application processing EPS/PS/PDF via Ghostscript |

### §2-3. PIL/Pillow Expression Evaluation

Python's Pillow library provides `ImageMath.eval()` for pixel-level arithmetic operations on images. When user input reaches the expression or environment parameters, Python code execution occurs.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`ImageMath.eval` environment injection** | The `environment` parameter of `PIL.ImageMath.eval()` allows injection of arbitrary Python objects. Attackers inject builtins or `__import__` references to achieve arbitrary code execution | Pillow ≤ 10.1.0 (CVE-2023-50447); any application passing user input to ImageMath.eval |
| **`ImageMath.eval` expression injection** | The `expression` parameter is evaluated as Python code. Unsanitized user input in the expression string enables direct code execution | Pillow ≤ 9.0.0 (CVE-2022-22817); applications using eval for dynamic image operations |

---

## §3. Media Codec & Container Processing

FFmpeg, GStreamer, and platform media frameworks process an enormous variety of audio/video codecs and container formats. This breadth creates exploitation surfaces through protocol handlers, playlist processing, codec parsing, and container metadata.

### §3-1. FFmpeg Protocol and Playlist Abuse

FFmpeg's extensive protocol support — designed for maximum format compatibility — creates exploitation paths where user-supplied media references trigger server-side requests or local file reads.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HLS playlist SSRF** | M3U8 playlists containing `http://internal-host/secret` as segment URIs force FFmpeg to make server-side requests, exfiltrating internal service responses as video data or leaking metadata endpoint credentials | FFmpeg processing user-supplied media URLs or uploaded playlists |
| **Concat protocol file read** | The `concat:` protocol concatenates data from multiple sources: `concat:file:///etc/passwd` reads local files and embeds content in the output stream | `concat` protocol not disabled; FFmpeg processing user-controlled URIs |
| **Subfile protocol arbitrary read** | `subfile,,start,0,end,100:file:///etc/shadow` reads byte ranges from arbitrary files | FFmpeg with subfile protocol enabled |
| **RTSP/RTP handler exploitation** | Crafted RTSP URLs trigger server-side network connections. Malformed RTSP responses can exploit parser vulnerabilities in the RTSP/RTP handling code | FFmpeg processing user-supplied streaming URLs |
| **Subtitle/attachment path traversal** | Subtitle streams or attached files within containers (MKV, MP4) can contain arbitrary data. FFmpeg extraction with path traversal in output naming writes files to arbitrary locations | FFmpeg used for automated media processing with extraction features |

### §3-2. Audio Codec Memory Corruption

Audio codecs parse complex bitstream structures (AAC headers, FLAC metadata blocks, Vorbis comment fields) where malformed input triggers heap corruption in decoding routines.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **FLAC metadata block overflow** | Oversized or malformed FLAC metadata blocks (VORBIS_COMMENT, PICTURE) trigger heap overflow during metadata parsing | FFmpeg FLAC decoder; libFLAC historical CVEs |
| **Opus/Vorbis packet corruption** | Crafted Opus or Vorbis packets with invalid channel mapping or window sizes trigger out-of-bounds writes during decoding | Media players, WebRTC pipelines |

### §3-3. Video Codec Parsing Vulnerabilities

Video codecs involve frame-by-frame parsing of complex prediction structures, motion vectors, and transform coefficients, each of which can trigger memory corruption when malformed.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JPEG2000 channel definition overflow** | Heap buffer overflow in JPEG2000 channel definition (`cdef`) atom parsing allows adjacent heap memory overwrite and potential code execution | FFmpeg jpeg2000dec |
| **JPEG XL integer overflow** | Integer overflow vulnerability in FFmpeg's JPEG XL parser and animation decoder components enables arbitrary code execution | FFmpeg before n6.1 |
| **VP9 decoder race condition** | Race condition in VP9 decoder creates data race during video encoding, potentially corrupting heap state | FFmpeg n7.0 (CVE-2024-36615) |
| **H.264/H.265 SPS/PPS malformation** | Crafted Sequence Parameter Sets or Picture Parameter Sets with invalid dimensions or reference counts trigger buffer overflows during decoder initialization | Various H.264/H.265 decoders |

---

## §4. Font Parsing RCE

Font files contain complex data structures — glyph outlines, hinting instructions, variable font axes, lookup tables, and embedded programs — parsed by libraries embedded in every operating system, browser, and document processor. Font parsing RCE is particularly dangerous because fonts are processed automatically during text rendering with no user interaction required.

### §4-1. TrueType/OpenType Parsing

TrueType fonts use quadratic Bézier curves and a stack-based hinting virtual machine. OpenType extends this with CFF (Compact Font Format) using cubic Bézier and a PostScript-like charstring interpreter.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CFF charstring stack overflow** | Malformed CFF charstring data overflows the PostScript interpreter stack during glyph rendering, corrupting adjacent memory | FreeType CFF parser; historical CVEs |
| **Variable font axis overflow** | Crafted variable font files with extreme axis values cause arithmetic overflows in interpolation calculations | FreeType variable font handling; OpenType 1.8+ variable fonts |

### §4-2. Web Font Decompression

Web fonts use specialized compression (WOFF/WOFF2 with zlib/Brotli) adding decompression as an additional attack surface layer before the font parser itself is reached.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WOFF2 Brotli decompression overflow** | Malformed WOFF2 files trigger buffer overflows during Brotli decompression in font loading paths, before font table parsing begins | Browser font loading; server-side font processing |
| **WOFF table directory corruption** | Crafted WOFF table directory entries specify conflicting sizes, causing heap corruption during table extraction | Browser engines; font subsetting tools |

### §4-3. Server-Side Font Processing

Server-side PDF generation, font subsetting for web delivery, and document conversion all parse and reconstruct font files, inheriting all parser vulnerabilities and adding new ones in the reconstruction logic.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Font subsetting library bugs** | Server-side font subsetting (for PDF generation, web font optimization) parses and reconstructs font files, triggering vulnerabilities in both parsing and serialization paths | HarfBuzz, fonttools, server-side PDF generators |
| **PHP font cache code injection** | PDF generation libraries (dompdf, TCPDF) convert font files to PHP code for caching. Crafted font metadata containing PHP code persists as executable `.php` files in the font cache directory | dompdf ≤ 1.2.0 (CVE-2022-28368); TCPDF (CVE-2024-56520); requires `$isRemoteEnabled=true` in dompdf |

---

## §5. PDF Parser Exploitation

PDF is an extraordinarily complex format — supporting JavaScript, embedded files, font programs, XRef tables, stream compression (14+ filters), interactive forms, digital signatures, and 3D annotations — making PDF parsers a persistent RCE target across native libraries, browser engines, and server-side processors.

### §5-1. PDF Viewer Memory Corruption

PDF viewers must parse the full complexity of the PDF specification, including multiple compression schemes, cross-reference tables, and embedded objects.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDFium use-after-free** | Complex annotation objects or cross-referenced page resources trigger use-after-free in Chrome's PDFium engine when memory management fails during multi-pass rendering | Chrome PDFium (CVE-2024-5846, CVE-2024-5847); browser-based PDF rendering |
| **PDFium heap buffer overflow** | Heap buffer overflow in PDFium when processing crafted PDF files, enabling out-of-bounds memory read and potential code execution | Chrome PDFium (CVE-2024-7973); crafted PDF files |
| **JBIG2 decoder exploitation** | Integer overflow in JBIG2 decoder within PDF rendering libraries enables out-of-bounds writes during symbol dictionary processing | Poppler (CVE-2022-38784); Xpdf; Apple CoreGraphics |
| **XRef table corruption** | Malformed cross-reference tables cause incorrect object resolution, leading to type confusion or use-after-free when objects are accessed via corrupted XRef entries | Various PDF libraries |
| **Stream decompression heap corruption** | Heavily compressed PDF streams (FlateDecode, LZWDecode, JBIG2Decode) trigger heap corruption during decompression when output exceeds allocated buffer | PDF processing pipelines without decompression limits |

### §5-2. PDF JavaScript Engine RCE

PDF files can contain embedded JavaScript for form calculation, validation, and interactive features. When PDF processors evaluate this JavaScript, the JavaScript engine becomes an attack surface.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDF.js type confusion** | Missing type checks when handling fonts in PDF.js enable type confusion that allows arbitrary JavaScript execution in the browser context — escalating from sandboxed PDF rendering to full page scripting | Mozilla PDF.js (CVE-2024-4367); affects Firefox, Thunderbird, and web applications embedding PDF.js |
| **Adobe Reader JavaScript sandbox escape** | Crafted JavaScript in PDF files exploits Adobe Reader's JavaScript engine to escape the sandbox and execute native code | Adobe Reader; historical CVEs with active exploitation |
| **Server-side JavaScript evaluation** | PDF processing libraries that evaluate embedded JavaScript for form pre-population or validation execute attacker-controlled code in the server context | Server-side PDF processing with JS evaluation enabled |

### §5-3. PDF as Exploit Container

PDF's extensibility makes it an ideal container for embedding exploits targeting downstream processors — Ghostscript for rendering, font parsers for text display, and image codecs for embedded graphics.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Ghostscript rendering chain** | PDFs rendered via Ghostscript inherit all PostScript sandbox escape vulnerabilities (§2-2). Ghostscript processes embedded PostScript fragments and font programs within PDFs | Server-side PDF thumbnail generation, conversion pipelines using Ghostscript |
| **Embedded font exploitation** | PDF files embed font programs (Type 1, CFF, TrueType) that are parsed by font libraries when the PDF is rendered, chaining into font parsing RCE (§4) | Any PDF renderer using FreeType or system font libraries |
| **Embedded image codec exploitation** | PDF files can embed images in JPEG2000, JBIG2, CCITT, and other formats. Malformed embedded images exploit codec vulnerabilities when the PDF is rendered | PDF renderers with vulnerable codec libraries |

---

## §6. Office Document Processing RCE

Server-side office document conversion (DOCX → PDF, XLSX → CSV, PPTX → HTML) typically uses LibreOffice in headless mode or specialized parsing libraries. Desktop office suites process documents with rich scripting and embedding capabilities. Both surfaces present RCE opportunities through macros, OLE embedding, equation editors, and format-specific parser bugs.

### §6-1. OLE and ActiveX Embedding

Object Linking and Embedding (OLE) allows Office documents to contain embedded objects from other applications, creating a cross-application attack surface.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Zero-click OLE heap overflow** | A zero-click vulnerability in Windows OLE enables RCE when Outlook processes RTF emails containing malformed OLE objects — no user interaction beyond email preview | Windows OLE (CVE-2025-21298, CVSS 9.8); zero-click via Outlook email preview |
| **Office security feature bypass** | Reliance on untrusted inputs in a security decision allows a local Microsoft Office security-feature bypass. Treat OLE/kill-bit mechanics as secondary attribution unless separately sourced; NVD/MSRC do not classify this as standalone RCE | Microsoft Office (CVE-2026-21509, CVSS 7.8, UI:R; CISA KEV) |
| **OLE Package file drop** | OLE Package objects embed arbitrary files. When processed, the embedded file is extracted to a temporary location and can be invoked via linked scripts or macros | Windows-based document processing; legacy OLE Package support |
| **ActiveX control instantiation** | Documents referencing ActiveX controls trigger control instantiation in the host process. Vulnerable or misconfigured controls provide code execution primitives | Internet Explorer/Office with ActiveX enabled; increasingly rare but still exploited |

### §6-2. Macro and Scripting Exploitation

Office document macros (VBA, Python-UNO, LibreOffice Basic) provide explicit code execution capabilities that can be triggered during document processing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **VBA auto-execute macros** | Macros triggered by document open events (`AutoOpen`, `Document_Open`, `Workbook_Open`) execute VBA code that spawns processes, downloads payloads, or directly manipulates the filesystem | Macro execution enabled; user clicks "Enable Content"; or Group Policy allows trusted locations |
| **DDE command injection** | Dynamic Data Exchange formulas in Office documents execute system commands: `=cmd\|'/c calc'!A0`. Works in both OLE and OOXML formats | DDE enabled; commonly used by APT28, FIN7 |
| **Template injection (remote template)** | OOXML documents reference remote `.dotm` template files via relationship entries. The template is fetched at open time and its macros execute, evading static analysis of the document itself | Network access to attacker server; macro execution settings may still apply |
| **Python-UNO bridge exploitation** | LibreOffice's Python-UNO bridge allows arbitrary Python code execution through internal API calls. The `unoconv` package exposed this to remote callers without authentication | CVE-2019-17400; server-side document conversion using unoconv |
| **Macro URL scheme invocation** | LibreOffice registers custom URL schemes (e.g., `vnd.sun.star.script:`) that can invoke internal macros with arbitrary arguments from browser links or document hyperlinks | LibreOffice (CVE-2025-1080); desktop or server with scheme handler registered |

### §6-3. Equation Editor and Legacy Component RCE

Legacy components maintained for backward compatibility often contain decades-old code with no modern security mitigations.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **EQNEDT32 stack buffer overflow** | Microsoft Equation Editor's font name processing uses a 40-byte local buffer. Font names exceeding 40 bytes overwrite the stack base pointer and return address, hijacking control flow to attacker-specified code | CVE-2017-11882, CVE-2018-0798; EQNEDT32.exe compiled without ASLR/DEP; exploited in the wild by FIN7, APT28, and others |
| **Equation OLE object exploitation** | Malicious Equation 3.0 OLE objects embedded in RTF or DOCX files trigger the vulnerable EQNEDT32.exe process, which calls `WinExec()` to execute attacker payloads | Windows with Equation Editor installed; most attacks via `.doc`/`.rtf` formats |
| **LibreOffice font-family path traversal** | Malformed `svg:font-family` values in ODF XML embed path traversal sequences. LibreOffice constructs temporary file paths using unsanitized font names, enabling `.ttf` file writes to arbitrary locations | LibreOffice ≤ 24.8.3 (CVE-2024-12425); server-side headless conversion → webshell deployment |

### §6-4. Office Format Parser Vulnerabilities

The sheer complexity of Office formats (OOXML with ZIP + XML + relationships + embedded media + VBA) creates parser-level vulnerability surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Generic Office RCE** | Security flaws in Office document parsing that allow crafted documents to execute code when opened — even in preview scenarios | Microsoft Office (CVE-2025-21365); affects Word, Excel, PowerPoint across Microsoft 365, Office 2019, Office 2021 |
| **Environment variable exfiltration** | INI file parsing within ODF documents extracts values from environment variables and filesystem files, leaking secrets from server-side conversion environments | LibreOffice ≤ 24.8.3 (CVE-2024-12426) |
| **OOXML XXE via XMLBeans** | Apache POI and similar Java-based OOXML parsers using XMLBeans ≤ 2.6.0 are susceptible to XXE during OOXML document parsing, enabling file read, SSRF, and potentially RCE chains | CVE-2014-3529, CVE-2019-12415; server-side document parsing with Apache POI |

### §6-5. Spreadsheet Format Conversion Exploitation

Server-side spreadsheet processing — importing CSV into XLSX, converting XLSX to PDF, generating reports from uploaded data files — creates unique attack surfaces distinct from general Office document risks. Spreadsheet conversion pipelines evaluate formulas, resolve external references, and process embedded objects during format transformation, making the conversion itself the exploitation trigger.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Formula Evaluation During Conversion** | Spreadsheet formulas (`=HYPERLINK()`, `=IMPORTDATA()`, `=WEBSERVICE()`) are evaluated during server-side format conversion (e.g., XLSX → PDF via LibreOffice). Formulas containing `=WEBSERVICE("http://169.254.169.254/")` trigger SSRF; formulas with `=CMD()` or `=SYSTEM()` (in certain engines) achieve command execution during the conversion process | Server-side conversion with formula evaluation enabled; LibreOffice Calc headless, Google Sheets API, Apache POI formula evaluator |
| **CSV Injection via Conversion Pipeline** | CSV files containing formula-prefixed cells (`=`, `+`, `-`, `@`) are imported into spreadsheet formats (XLSX, ODS) where the values are reinterpreted as formulas. Server-side conversion then evaluates these formulas, triggering SSRF, file read, or command execution during the import-to-export pipeline | CSV → XLSX/ODS → PDF conversion chain; no cell value sanitization at import stage |
| **OLE Object Activation in Conversion** | Spreadsheet files containing embedded OLE objects (charts linking to external data, embedded executables, ActiveX controls) trigger object activation when the document is opened for conversion. LibreOffice headless mode and some conversion APIs process embedded objects, potentially executing linked content | Server-side conversion that processes embedded OLE objects; no sandboxing of OLE activation |
| **Macro Execution in Headless Conversion** | Spreadsheet macros (VBA in XLSX, LibreOffice Basic in ODS) execute during server-side headless conversion if macro execution is not explicitly disabled. Auto-execute macros (`Workbook_Open`, `Auto_Open`) trigger on document load | LibreOffice/OpenOffice headless conversion without `--norestore --nofirststartwizard --nologo --nocrashreport --nolockcheck` and macro disabling flags |

---

## §7. Metadata Processing RCE

Metadata extraction libraries parse complex embedded structures (EXIF, XMP, IPTC, DjVu annotations, ICC profiles) within media files. When metadata values flow into eval-like contexts or interpreter back-channels, code execution occurs entirely through "data" fields.

### §7-1. Interpreter Injection via Metadata

Some metadata processing tools evaluate portions of metadata content using scripting language interpreters, creating injection vectors through crafted metadata values.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ExifTool DjVu annotation Perl injection** | DjVu annotation strings are passed to Perl's `eval()` during ExifTool's ANT chunk parsing. Crafted annotations containing Perl code — including backtick shell commands — execute with ExifTool's privileges | ExifTool 7.44–12.23 (CVE-2021-22204); critical impact: unauthenticated RCE in GitLab via Workhorse (CVE-2021-22205) |
| **ExifTool polyglot file exploitation** | The DjVu injection can be embedded within valid JPEG, TIFF, or other image formats as a polyglot — a file valid in multiple formats. The outer format passes validation while the inner DjVu payload triggers ExifTool's vulnerable code path | Any application using ExifTool for metadata stripping/extraction on user uploads |

### §7-2. XML Entity Expansion in Metadata

XMP (Extensible Metadata Platform) metadata blocks use XML format. Metadata parsers that process XMP without disabling external entity resolution enable XXE-based attack chains.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XMP metadata XXE → SSRF → RCE** | XMP metadata blocks embedded in images/documents contain XML with external entity references. Processing triggers SSRF to internal services, potentially chaining to RCE via internal API abuse | Libraries parsing XMP without disabling external entities |
| **ICC profile malformation** | Crafted ICC color profiles embedded in images trigger parsing errors that leak memory or cause heap corruption during color management operations | Image processing with ICC profile support; historical pattern across multiple libraries |

---

## §8. XML/Markup Document Processing

XML, SVG, and XSLT processing engines provide rich feature sets that, when exposed to attacker-controlled input, enable code execution through entity expansion, extension functions, and embedded scripting.

### §8-1. XSLT Extension Function RCE

XSLT processors support extension functions that invoke native code. When attackers control XSLT stylesheets or can inject XSLT fragments, extension functions provide direct code execution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Java XSLT extension functions** | Malicious XSL stylesheets embed Java extension functions that are executed by the Java XSLT processor (Xalan, Saxon) during transformation. Attackers force the server to fetch and process a malicious XSL file | Oracle E-Business Suite (CVE-2025-61882, critical); any application processing user-controlled XSLT |
| **XSLT `document()` function SSRF** | The `document()` function loads external XML resources. Crafted XSLT stylesheets use `document()` to trigger server-side requests to internal services or cloud metadata endpoints | Any XSLT processor with `document()` enabled |
| **PHP `xsl:registerPHPFunctions`** | PHP's XSL extension allows registering PHP functions as XSLT extension functions. Crafted XSLT can call `system()`, `exec()`, or other dangerous PHP functions | PHP applications processing user-controlled XSLT with registerPHPFunctions |
| **.NET XSLT scripting** | .NET's `XslCompiledTransform` supports embedded C#/VB.NET script blocks in XSLT. When `EnableScript` is true, crafted XSLT executes arbitrary .NET code | ASP.NET applications with XSLT scripting enabled |

### §8-2. SVG Processing Exploitation

SVG (Scalable Vector Graphics) is an XML-based format that supports JavaScript, external resource loading, and in some renderers, Java extension functions. Server-side SVG processing for image generation or conversion exposes these capabilities.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG JavaScript execution** | SVG `<script>` elements execute JavaScript when rendered with a proper `Content-Type` of `image/svg+xml`. Server-side SVG-to-raster conversion may execute embedded scripts | Server-side SVG rendering with JavaScript-capable renderer |
| **SVG XXE/SSRF** | SVG files contain XML DTD declarations that trigger external entity resolution, enabling file read and SSRF during server-side processing | Server-side SVG parsing without XXE protection |
| **Apache Batik Java JAR execution** | Apache Batik's SVG renderer allows `<script type="application/java-archive">` elements referencing JAR files. The referenced JAR's code executes during SVG rendering | Apache Batik-based SVG processing (e.g., report generation, PDF creation) |
| **SVG `<foreignObject>` HTML injection** | SVG `<foreignObject>` elements embed HTML content. Server-side SVG processors that render HTML within foreignObject may trigger additional parser vulnerabilities or script execution | SVG renderers supporting foreignObject with HTML rendering |

### §8-3. XXE in Document Parsers

XML External Entity injection remains a prevalent attack against document processing libraries that parse XML-based formats (OOXML, ODF, SVG, XHTML, EPUB) without disabling entity resolution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **OOXML/ODF XXE** | Office document formats (DOCX, XLSX, PPTX, ODT) are ZIP archives containing XML files. Parsers that extract and process these XML files without disabling external entities enable XXE | Apache POI, server-side OOXML processing |
| **EPUB XXE** | EPUB e-book format contains XHTML content files and OPF metadata in XML. EPUB parsers that process these without XXE protection enable file read and SSRF | Server-side EPUB processing, e-book conversion pipelines |
| **XML-based configuration injection** | Document processing pipelines that load XML configuration files (XMP, XFDF, XDP) from user-controlled sources enable entity injection in the configuration parsing stage | PDF form processing, document workflow systems |

---

## §9. HTML-to-Document Conversion RCE

HTML-to-PDF/image conversion tools (wkhtmltopdf, Puppeteer/Playwright, headless Chrome, dompdf, WeasyPrint) render HTML content server-side. Because these tools process HTML "as a browser would," they inherit the full web attack surface — SSRF, local file inclusion, JavaScript execution — in a server-side context with elevated privileges.

### §9-1. Headless Browser SSRF and File Inclusion

Headless browsers (wkhtmltopdf, Puppeteer, Playwright) fetch external resources (images, stylesheets, iframes) during HTML rendering, enabling server-side request forgery when user input controls the HTML being converted.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Iframe-based SSRF** | HTML content containing `<iframe src="http://169.254.169.254/latest/meta-data/">` causes the headless browser to fetch cloud metadata, embedding credentials in the generated PDF | wkhtmltopdf (CVE-2022-35583, CVSS 9.8); Puppeteer without URL restrictions; any HTML-to-PDF with resource loading |
| **CSS `@import` / `url()` SSRF** | CSS `@import` rules and `url()` references in stylesheets trigger server-side resource fetches. Attackers chain CSS processing to probe internal networks | Headless browsers processing user-controlled CSS |
| **Local file read via `file://`** | HTML containing `<iframe src="file:///etc/passwd">` or `<link href="file:///etc/shadow">` causes the headless browser to read local files and embed content in output | wkhtmltopdf without `--disable-local-file-access`; Puppeteer with `file://` protocol allowed |
| **JavaScript execution in server context** | User-controlled HTML containing `<script>` tags executes JavaScript in the headless browser. This JavaScript can perform XMLHttpRequest to internal services, read local files via various APIs, or exploit browser vulnerabilities | Headless browsers without JavaScript disabled; most converters enable JS by default |
| **Redirect-based filter bypass** | Initial URL passes validation but HTTP redirect chains lead to internal/restricted resources. The headless browser follows redirects and processes the final destination content | Converters with URL allowlists but without redirect validation |
| **Single-pass keyword-strip bypass** | HTML sanitizer uses non-recursive string replacement (`str_ireplace` or equivalent) to remove dangerous tags (`iframe`, `embed`, `file:/`). Attacker nests the blocked keyword within itself — `<ifraiframeme>` becomes `<iframe>` after one strip pass, `filfile:/e:///` becomes `file:///` — reconstructing the dangerous payload post-filter. Combined with Chromium-based PDF rendering (`--no-sandbox`), this enables SSRF and local file read (CVE-2025-0474, Invoice Ninja ≤ 5.10.43) | Single-pass string replacement sanitizer; headless browser PDF renderer (Snappdf/Chromium) |

### §9-2. PHP PDF Library Code Injection

PHP-based PDF generation libraries (dompdf, TCPDF, mPDF) that process user-controlled HTML/CSS introduce code execution paths through font handling, template injection, and deserialization.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **dompdf font cache PHP injection** | dompdf processes CSS `@font-face` rules by downloading font files and saving them with a `.php` extension in the font cache directory. A crafted font file (TTF+PHP polyglot) containing PHP code becomes web-accessible and executable | dompdf ≤ 1.2.0 (CVE-2022-28368); `$isRemoteEnabled=true`; font cache directory web-accessible |
| **TCPDF font metadata PHP injection** | TCPDF converts font files to PHP source code for caching. Crafted font metadata containing PHP code persists as executable PHP in the generated font file | TCPDF < 6.8.0 (CVE-2024-56520); applications converting attacker-controlled fonts |
| **PHP deserialization in PDF metadata** | Some PHP PDF libraries use `unserialize()` on cached data structures. Crafted cache files containing serialized PHP objects trigger gadget chains | PHP PDF libraries with file-based caching |
| **Resource loader Phar deserialization** | PHP PDF libraries calling `file_exists()` or `getimagesize()` on user-controlled resource paths trigger `phar://` stream wrapper deserialization. In spipu/html2pdf, `<cert src="phar://uploaded.png">` reaches `file_exists()`, deserializing the Phar manifest in an uploaded polyglot and executing `__destruct()` gadget chains | PHP < 8.0; file upload placing Phar archive on server; spipu/html2pdf ≤ 5.3.0 |
| **Path traversal via encoding bypass** | PDF renderers filter literal `../` in resource paths but fail to account for URL-encoded variants. TCPDF validates then calls `urldecode()` — attackers supply `..%2f` or double-encoded `%252f..` to traverse directories and embed arbitrary server files as images in the generated PDF | TCPDF 6.8.0–6.8.2; any PHP PDF library performing path traversal checks before URL decoding of resource URIs |
| **Security hook timing bypass** | PDF libraries with pluggable security interfaces execute resource loading under the default permissive handler before the custom security implementation is initialized. In spipu/html2pdf 5.3.1, `_drawImage()` fires SSRF requests before custom restrictions take effect — a "hook runs too late" race | spipu/html2pdf 5.3.1; application relying on custom security handler to restrict resource loading |

---

## §10. Archive Processing RCE

Archive formats (ZIP, TAR, RAR, 7z, and derived formats like JAR, WAR, APK, IPA, DOCX, EPUB) require extraction before the contained files can be processed. Vulnerabilities in extraction logic — particularly path validation — enable arbitrary file writes that chain into code execution.

### §10-1. Path Traversal via Archive Entries (Zip Slip)

Archive entries containing path traversal sequences (`../../`) in their filenames write extracted files outside the intended destination directory when extraction code fails to validate entry paths.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic Zip Slip path traversal** | Archive entries with filenames like `../../../../var/www/html/shell.php` write files outside the extraction directory. The attacker overwrites executable files, cron jobs, SSH authorized_keys, or deploys webshells | Archive extraction without entry path validation; affects Go, Java, Python, Ruby, .NET libraries |
| **Symlink-based traversal** | Archive entries create symbolic links pointing to sensitive locations (`/etc/passwd`, `/var/www/html/`). Subsequent entries writing to the symlink name actually write to the symlink target | CVE-2025-3445 (mholt/archiver); extractors that create symlinks before validating targets |
| **Double extraction bypass** | First extraction writes a symlink; second extraction (or processing of extracted archives) follows the symlink to write to arbitrary locations | Multi-stage extraction pipelines; recursive archive processing |
| **Unicode normalization bypass** | Path validation checks ASCII traversal sequences but Unicode normalization converts alternative representations (fullwidth `．．/`, decomposed characters) into traversal sequences after validation | Extractors with insufficient Unicode normalization handling |

### §10-2. Archive Parser Memory Corruption

Archive format parsers themselves contain memory corruption vulnerabilities in header parsing, compression handling, and metadata processing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RAR path validation RCE** | Insufficient validation of attacker-injected relative paths in WinRAR enables code execution through crafted RAR archives | WinRAR ≤ 7.12; archive extraction with path validation bypass |
| **7z LZMA decompression overflow** | Crafted 7z archives trigger heap buffer overflow during LZMA/LZMA2 decompression | 7-Zip, libarchive LZMA handling |
| **Nested archive bomb** | Archives containing deeply nested archives (ZIP within ZIP within ZIP) exhaust stack or heap during recursive extraction | Recursive extraction pipelines without depth limits |

---

## §11. Antivirus & Security Scanner Processing RCE

A particularly ironic attack class: security tools designed to detect malicious files must parse those same file formats, inheriting all parser vulnerabilities. Since security scanners run with elevated privileges and process every file on a system, parser vulnerabilities in scanners have outsized impact.

### §11-1. ClamAV Parser Vulnerabilities

ClamAV implements parsers for hundreds of file formats to detect embedded malware. Each parser is a potential attack surface.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDF parser buffer overflow** | Buffer overflow write in ClamAV's PDF file parser enables arbitrary code execution when scanning crafted PDF files with specific max file-size and scan-size configurations | ClamAV (CVE-2025-20260, CVSS 9.8); when max file-size ≥ 1024MB and max scan-size ≥ 1025MB |
| **HFS+ partition parser RCE** | Crafted HFS+ partition files submitted for scanning trigger heap buffer overflow, enabling RCE with ClamAV's scanning process privileges | ClamAV (CVE-2023-20032, CVSS 9.8) |
| **UDF file parser information leak** | Buffer overflow read in UDF file parser causes information disclosure via temporary files or application crash | ClamAV (CVE-2025-20234) |

### §11-2. General Security Tool Parser RCE

The pattern extends beyond ClamAV to any security tool that parses file formats.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Antivirus engine format confusion** | Security scanners auto-detect file formats via magic bytes. Polyglot files appear as one format to the scanner but another to the target application, evading detection while delivering exploitation payloads | Any AV engine using magic-byte-based format detection |
| **Email gateway document parsing** | Email security gateways parse attachments (PDF, Office, archives) for threat detection, running the same vulnerable parsers as the applications they protect | Enterprise email gateways; attachment scanning infrastructure |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Server-side file upload processing** | User uploads image/document → server processes (resize, convert, extract metadata) → stores result | §1 + §2 + §7 + §10 |
| **Document conversion pipeline** | User submits document → server converts (DOCX→PDF, HTML→PDF, EPS→PNG) → returns result | §2 + §5 + §6 + §9 |
| **Thumbnail/preview generation** | System auto-generates thumbnails for uploaded files or linked URLs | §1 + §2 + §5 |
| **Email attachment processing** | Email gateway scans and/or renders attachments for preview or threat detection | §5 + §6 + §11 |
| **Mobile zero-click exploitation** | Attacker sends crafted media via messaging app → device auto-processes without user interaction | §1 (JBIG2) + §3 (CoreAudio) + §4 (FreeType) + §5 (FORCEDENTRY) |
| **CI/CD build pipeline** | Build system processes artifacts, documents, or assets containing crafted files | §6 + §8 + §10 |
| **Cloud image optimization** | CDN or cloud service resizes/transcodes user-uploaded or URL-referenced images | §1 + §2 + §3 |
| **Antivirus/security scanning** | Security tool parses uploaded files for malware detection | §11 + all format-specific sections |
| **Browser rendering** | Browser processes crafted PDF, font, image, or SVG during normal web browsing | §1 + §4 + §5 + §8 |
| **API-driven media processing** | SaaS APIs for OCR, transcription, format conversion process user-supplied files | §1 + §2 + §3 + §5 + §7 |

---

## CVE / Bounty Mapping (2021–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §5-3 (JBIG2 Turing-complete) | CVE-2021-30860 (Apple CoreGraphics) — FORCEDENTRY | Zero-click iMessage → full device compromise. NSO Group Pegasus spyware deployment. "Most technically sophisticated exploit ever seen" — Google Project Zero |
| §2-2 (GS format string sandbox escape) | CVE-2024-29510 (Ghostscript ≤ 10.03.0) | Actively exploited in the wild. EPS files disguised as JPEGs bypass validation for shell access |
| §2-2 (GS OCR device abuse) | CVE-2024-29511 (Ghostscript ≤ 10.03.0) | Arbitrary file read/write via Ghostscript OCR device |
| §4-1 (FreeType subglyph overflow) | CVE-2025-27363 (FreeType ≤ 2.13.0) | CVSS 8.1. Actively exploited zero-click. CISA KEV catalog. Affects billions of devices (Android, Linux, ChromeOS) |
| §3-2 (CoreAudio AAC heap corruption) | CVE-2025-31200 (iOS CoreAudio) | Zero-day zero-click RCE via iMessage. Patched iOS 18.4.1 |
| §6-1 (OLE zero-click heap overflow) | CVE-2025-21298 (Windows OLE) | CVSS 9.8. Zero-click via Outlook email preview. RTF document exploit |
| §6-1 (Office security feature bypass) | CVE-2026-21509 (Microsoft Office) | CVSS 7.8. CISA KEV. Local/UI-required Office security feature bypass; not a standalone RCE per NVD/MSRC description |
| §11-1 (ClamAV PDF parser overflow) | CVE-2025-20260 (ClamAV) | CVSS 9.8. RCE via PDF scanning in antivirus engine |
| §11-1 (ClamAV HFS+ parser RCE) | CVE-2023-20032 (ClamAV) | CVSS 9.8. RCE via crafted HFS+ partition in antivirus scan |
| §1-1 (WebP Huffman overflow) | CVE-2023-4863 (libwebp; CVE-2023-5129 rejected as duplicate) | NVD/CISA-ADP CVSS 8.8. Affects products that bundle vulnerable libwebp versions and expose the lossless-WebP decoding path to attacker-controlled content |
| §5-2 (PDF.js type confusion) | CVE-2024-4367 (Mozilla PDF.js) | Arbitrary JS execution in browser context via crafted PDF |
| §1-2 (libpng heap overflow) | CVE-2025-65018 (libpng 1.6.0–1.6.50) | Heap buffer overflow in 16-bit interlaced PNG processing |
| §1-2 (libtiff write-what-where) | CVE-2025-9900 (libtiff) | Write-what-where vulnerability enabling memory corruption |
| §1-2 (Poppler ref count overflow) | CVE-2025-52886 (Poppler ≤ 25.06.0) | Use-after-free via atomic_int reference count overflow |
| §7-1 (ExifTool DjVu injection) | CVE-2021-22204 / CVE-2021-22205 (ExifTool/GitLab) | Unauthenticated RCE in GitLab. $20,000 bounty. Widely exploited |
| §6-3 (Equation Editor stack overflow) | CVE-2017-11882 / CVE-2018-0798 (EQNEDT32) | Ubiquitous exploitation by APT groups. No ASLR/DEP on EQNEDT32.exe |
| §9-1 (wkhtmltopdf SSRF) | CVE-2022-35583 (wkhtmltopdf) | CVSS 9.8. SSRF via iframe injection in HTML-to-PDF conversion |
| §9-1 (Single-pass keyword-strip bypass) | CVE-2025-0474 (Invoice Ninja ≤ 5.10.43) | SSRF + arbitrary file read via Snappdf/Chromium; non-recursive `str_ireplace` filter bypass |
| §4-3 (dompdf font cache injection) | CVE-2022-28368 (dompdf ≤ 1.2.0) | TTF+PHP polyglot file → webshell via font cache |
| §4-3 (TCPDF font PHP injection) | CVE-2024-56520 (TCPDF < 6.8.0) | PHP code injection via crafted font metadata |
| §8-1 (Java XSLT extension RCE) | CVE-2025-61882 (Oracle E-Business Suite) | Critical. Unauthenticated RCE via XSLT extension functions. Actively exploited |
| §6-3 (LibreOffice font path traversal) | CVE-2024-12425 (LibreOffice ≤ 24.8.3) | Arbitrary file write via font-family path traversal in server-side conversion |
| §2-1 (ImageMagick delegate injection) | CVE-2016-3714 (ImageMagick) — ImageTragick | Shell command execution via crafted image filenames. Massive impact on web applications |
| §1-1 (FFmpeg PNM overflow) | CVE-2024-7055 (FFmpeg ≤ 7.0.1) | Heap buffer overflow in PNM frame decoder |
| §10-1 (Zip Slip path traversal) | Multiple CVEs across ecosystems | Arbitrary file write → webshell. Affects Java, Go, Python, Ruby, .NET |
| §9-2 (Resource loader Phar deserialization) | — (PT SWARM research, 2025) | Phar deserialization via `file_exists()` in spipu/html2pdf ≤ 5.3.0; RCE chain through `__destruct()` gadgets |
| §9-2 (Path traversal encoding bypass) | — (PT SWARM research, 2025) | TCPDF 6.8.0–6.8.2; URL-encoded/double-encoded path traversal bypasses `../` filter in resource loading |
| §9-2 (Security hook timing bypass) | — (PT SWARM research, 2025) | spipu/html2pdf 5.3.1; SSRF via resource load before custom security handler initialization |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **AFL++ / AFL** | Any C/C++ parser (libpng, libtiff, FFmpeg, etc.) | Coverage-guided mutation fuzzing with compile-time instrumentation; discovers heap overflows, UAFs, integer overflows |
| **libFuzzer** | Individual parsing functions | In-process coverage-guided fuzzing; ideal for targeted function-level fuzzing of image/font/codec parsers |
| **OSS-Fuzz** | Open-source C/C++ projects (libpng, libtiff, FreeType, FFmpeg, Poppler, etc.) | Continuous fuzzing infrastructure; automatically discovers and reports vulnerabilities |
| **ImageTragick Scanner** | ImageMagick installations | Tests for delegate command injection via crafted MVG/SVG files |
| **Ghostscript exploit kits** | Ghostscript sandbox | Automated testing of `-dSAFER` bypass techniques via format string, pipe device, and OCR abuse |
| **Slip (archive tool)** | ZIP, TAR, 7z archive extraction | Creates malicious archives with path traversal payloads for Zip Slip testing |
| **Gopherus** | SSRF → RCE chains | Generates Gopher protocol payloads for Redis, MySQL, and other internal services reachable via SSRF |
| **dompdf-rce (Positive Security)** | dompdf font cache | Automated exploit for dompdf TTF+PHP polyglot font cache injection |
| **ExifTool CVE-2021-22204 PoC** | ExifTool metadata processing | Generates DjVu annotation payloads embedded in polyglot image files |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **ImageMagick `policy.xml`** | ImageMagick delegate/protocol restrictions | Disables dangerous delegates (MVG, MSL, EPHEMERAL, URL, HTTPS), limits resource consumption, restricts file operations |
| **Ghostscript `-dSAFER` + version pinning** | Ghostscript sandbox | Enables sandbox restrictions (though historical bypasses exist); keeping current version is critical |
| **Content Disarmament and Reconstruction (CDR)** | All document/image formats | Strips embedded scripts, macros, active content from documents before processing; reconstructs sanitized versions |
| **ImSan** | Image polyglot detection | Sanitizes image files by stripping extraneous content that enables polyglot exploitation |
| **seccomp / AppArmor profiles** | Processing library sandboxing | Restricts system calls available to image/document processing processes (filesystem, network, exec) |
| **gVisor / Firecracker** | Container-level sandboxing | Runs document processing in microVM or user-space kernel to contain exploitation |
| **Nsjail / Bubblewrap** | Process-level sandboxing | Lightweight namespace-based sandboxing for individual processing operations |
| **ClamAV / YARA rules** | Malicious file detection | Pattern matching against known exploitation payloads in documents and media files |

---

## References

- Codean Labs — CVE-2024-29510: Exploiting Ghostscript using Format Strings (2024)
- Codean Labs — CVE-2024-29511: Abusing Ghostscript's OCR Device (2024)
- Google Project Zero — A Deep Dive into an NSO Zero-Click iMessage Exploit: FORCEDENTRY (2021)
- Google Project Zero — FORCEDENTRY: Sandbox Escape (2022)
- Citizen Lab — FORCEDENTRY: NSO Group iMessage Zero-Click Exploit (2021)
- Positive Security — From XSS to RCE (dompdf 0day) (2022)
- NCC Group — Technical Advisory: Multiple Vulnerabilities in TCPDF (2024)
- HackerOne — Vulnerability Deep Dive: Gaining RCE Through ImageMagick with Frans Rosen
- Snyk Research — Zip Slip Vulnerability (2018)
- Intigriti — Exploiting PDF Generators: Complete Guide to SSRF Vulnerabilities
- PortSwigger — Web Security Academy: XXE, SSRF, XSLT Injection
- Allan Wirth — SVG Cheatsheet: Exploiting Server-Side SVG Processors
- Apple Security Advisory — iOS 18.4.1: CVE-2025-31200, CVE-2025-31201
- Meta Security Advisory — FreeType CVE-2025-27363
- Microsoft Security Response Center — CVE-2025-21298, CVE-2026-21509
- ClamAV Security Advisories — CVE-2025-20260, CVE-2025-20234
- Cloudflare Blog — Uncovering the Hidden WebP Vulnerability (CVE-2023-4863)
- [NVD: CVE-2023-4863](https://nvd.nist.gov/vuln/detail/CVE-2023-4863)
- [NVD: rejected duplicate CVE-2023-5129](https://nvd.nist.gov/vuln/detail/CVE-2023-5129)
- ImageTragick.com — ImageMagick CVE-2016-3714 Advisory
- arxiv.org — Where the Polyglots Are: How Polyglot Files Enable Cyber Attack Chains (2024)
- TU Braunschweig — Server-Side Browsers: Exploring the Web's Hidden Attack Surface
- [Emil Lerner — "HotPics 2021: The Current State of Server-Side Image Conversion Attacks" (ZeroNights X, 2021). Survey of ImageMagick, Ghostscript, Pillow exploitation including Ghostscript zero-day achieving bounties at Airbnb, Dropbox, and Yandex.](https://www.slideshare.net/neexemil/hotpics-2021)
- [PT SWARM — "Blind trust: what is hidden behind the process of creating your PDF file?" (2025). Path traversal encoding bypass, Phar deserialization, and security hook timing bypass in TCPDF, spipu/html2pdf, mpdf, and jsPDF.](https://swarm.ptsecurity.com/blind-trust-what-is-hidden-behind-the-process-of-creating-your-pdf-file/)
