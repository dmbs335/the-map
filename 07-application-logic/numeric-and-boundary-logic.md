# Numeric and Boundary Logic — Mutation/Variation Taxonomy

---
## Classification Structure

This taxonomy organizes the entire attack surface of numeric and boundary logic vulnerabilities under three orthogonal axes. Every technique is classified by **what numeric property is mutated** (Axis 1), **what discrepancy the mutation creates** (Axis 2), and **in what deployment scenario the mutation becomes exploitable** (Axis 3).

**Axis 1 (Mutation Target)** structures the main body of this document. It identifies the specific numeric property or operation being abused: integer arithmetic bounds, type representation, floating-point behavior, string-to-number parsing, boundary conditions, allocation sizing, business logic numerics, and concurrency windows on numeric state.

**Axis 2 (Discrepancy Type)** is the cross-cutting dimension. It explains *why* each mutation works — what mismatch or inconsistency the attacker exploits between what the developer assumed and what actually happens at runtime.

| Discrepancy Type | Description |
|---|---|
| **Wraparound Mismatch** | Value exceeds type capacity and silently wraps to an unintended value |
| **Representation Mismatch** | Signed/unsigned, width, or type-level disagreement between producer and consumer |
| **Precision Mismatch** | Rounding, truncation, or floating-point approximation diverges from expected exact value |
| **Validation Bypass** | Special values (NaN, Infinity, -0), type juggling, or format tricks evade checks |
| **Semantic Mismatch** | Negative where positive expected, zero where non-zero expected, or domain-invalid value |
| **Allocation Mismatch** | Computed buffer/object size diverges from actual data size due to numeric error |
| **Temporal Mismatch** | Numeric state changes between check and use due to concurrency |

**Axis 3 (Attack Scenario)** maps each mutation to its real-world impact context — memory corruption, authentication bypass, financial manipulation, denial of service, smart contract exploitation, or privilege escalation.

### Foundational Principle

All numeric and boundary logic vulnerabilities stem from a single root cause: **the gap between mathematical integers (infinite, exact) and machine integers (finite, typed, approximated)**. Every programming language and runtime makes trade-offs in how it represents, converts, and operates on numbers. Attackers exploit the points where these trade-offs create observable or manipulable differences from developer expectations.

---

## §1. Integer Arithmetic Overflow and Underflow

Integer overflow and underflow occur when an arithmetic operation produces a result outside the representable range of the target integer type. The behavior varies by language: C/C++ treat signed overflow as undefined behavior; unsigned overflow wraps modulo 2^N; Java wraps silently; Rust panics in debug mode and wraps in release; Solidity <0.8 wraps silently; Solidity ≥0.8 reverts unless `unchecked`.

### §1-1. Unsigned Integer Wraparound (Overflow)

When an unsigned integer exceeds its maximum value (e.g., 2^32 - 1 for uint32, 2^256 - 1 for uint256), it wraps to zero and continues counting upward from there.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Addition Wraparound** | `a + b` where result > MAX wraps to `(a + b) mod 2^N` | No overflow check before arithmetic |
| **Multiplication Wraparound** | `a * b` wraps when product exceeds type range; particularly dangerous in size calculations like `count * element_size` | Multiplication used in allocation or loop bound |
| **Post-Increment Wraparound** | Counter or accumulator incremented past MAX in a loop, wrapping to zero and restarting | Unbounded loop without termination check on counter |
| **Shift Overflow** | Left-shifting a value beyond bit width produces zero or wraps | Shift amount not validated against type width |

**Example**: `uint32_t alloc_size = count * sizeof(element);` — if `count` is 0x40000001 and `sizeof(element)` is 4, the product wraps to 0x00000004, allocating a 4-byte buffer for billions of elements.

### §1-2. Unsigned Integer Underflow (Subtraction Wrap)

When an unsigned integer goes below zero, it wraps to the maximum value of its type.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Subtraction Underflow** | `a - b` where `a < b` wraps to `MAX - (b - a - 1)` | No check that `a >= b` before subtraction |
| **Decrement Past Zero** | Counter decremented below zero wraps to MAX | Loop or balance tracking without floor check |
| **Length Subtraction** | `buffer_len - header_len` underflows when header exceeds buffer | Length fields from untrusted input |

**Example**: In Ethereum smart contracts pre-Solidity 0.8, `balances[msg.sender] - value` where `value > balance` would wrap to ~2^256, granting the attacker an astronomical token balance. The BEC token exploit (CVE-2018-10299) is commonly cited for this pattern — though the official description classifies it as an integer overflow in `batchTransfer` multiplication (`value * cnt`), not a subtraction underflow — causing large notional losses.

### §1-3. Signed Integer Overflow

Signed integer overflow is undefined behavior in C/C++, meaning the compiler may assume it never happens and optimize accordingly. This creates particularly dangerous conditions where security checks are eliminated by the optimizer.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Signed Addition Overflow** | `INT_MAX + 1` is UB in C; may wrap, trap, or be optimized away | Compiler assumes no signed overflow for optimizations |
| **Signed Negation Overflow** | `-INT_MIN` overflows because `|INT_MIN| > INT_MAX` in two's complement | Absolute value computation on unchecked input |
| **Optimized-Away Check** | `if (x + offset < x)` check removed by compiler because signed overflow is UB | Security check relies on overflow detection via comparison |
| **Division Overflow** | `INT_MIN / -1` overflows (result would be INT_MAX + 1) | Division with attacker-controlled divisor |

**Example**: A bounds check like `if (offset + len < offset) return ERROR;` may be completely removed by an optimizing compiler, because signed overflow is undefined, and therefore the compiler concludes the condition can never be true.

---

## §2. Type Representation and Conversion Errors

These vulnerabilities arise when numeric values are converted between types of different sizes, signedness, or representation — either implicitly by the language or explicitly by the programmer.

### §2-1. Signedness Mismatch

Occurs when a signed value is interpreted as unsigned (or vice versa), causing a negative number to become an extremely large positive number, or a large unsigned value to become negative.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Signed-to-Unsigned Promotion** | Negative `int` cast to `size_t` becomes a huge positive value | Length/size parameter accepted as signed, used as unsigned |
| **Unsigned-to-Signed Narrowing** | Large `unsigned` value interpreted as negative `int`, passing "is positive" checks | Comparison between signed and unsigned operands |
| **Implicit Promotion in Comparison** | C's integer promotion rules silently convert signed to unsigned in mixed comparisons | `if (signed_len < unsigned_max)` where `signed_len` is negative |
| **Sign Extension** | Casting a signed `char` (-128..127) to `int` sign-extends the high bits; 0xFF becomes 0xFFFFFFFF (-1) rather than 255 | Network protocol parsing, character handling |

**Example**: A packet parser reads a length field as `int16_t length = read_short(packet)`. A value of -1 (0xFFFF) passes the check `if (length > MAX_LEN) return ERROR` (since -1 < MAX_LEN). When passed to `memcpy(dst, src, length)`, the signed value is implicitly converted to `size_t` (unsigned), becoming 0xFFFF or 0xFFFFFFFFFFFFFFFF on 64-bit systems, causing a massive buffer overflow.

### §2-2. Integer Truncation

Occurs when a value is stored in a type too small to hold it, silently discarding the high-order bits.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Width Narrowing** | Casting `int64` to `int32` or `int32` to `int16` drops high bits | Cross-boundary data transfer between different-width types |
| **Modular Truncation** | Value `v` stored as `v mod 2^N` where N is the narrower bit width | Allocation size computed in wider type, stored in narrower |
| **Pointer/Size Truncation** | 64-bit size truncated to 32-bit on mixed-architecture code | 32-bit/64-bit interop, WoW64 on Windows |
| **Return Value Truncation** | Function returns wider type than caller expects; high bits silently dropped | API mismatch between library and caller |

**Example**: CVE-2025-49679 — a numeric truncation vulnerability in the Windows Shell allowed local privilege escalation to SYSTEM level (CVSS 7.8), caused by truncation in legacy numeric handling components.

### §2-3. Type Coercion and Juggling

Dynamic languages automatically convert between types during comparisons and operations, creating opportunities for semantic confusion.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PHP Loose Comparison (==)** | `"0e12345" == "0e67890"` evaluates to `true` because both are interpreted as 0.0 in scientific notation | Password hash comparison using `==` instead of `===` |
| **PHP Magic Hash** | Hash values starting with `0e[digits]` are treated as float zero, bypassing hash comparisons | MD5/SHA1 hash compared with loose equality |
| **JavaScript Type Coercion** | `[] == false` is `true`; `"" == 0` is `true`; `null == undefined` is `true` | Input validation using `==` or truthy/falsy checks |
| **JavaScript parseInt Truncation** | `parseInt("5e-7")` returns `5` (parses "5" then stops at "e"); `parseInt([1,2,3])` returns `1` | Numeric parsing of untrusted input without strict validation |
| **Numeric String Auto-Conversion** | Languages interpret strings like `"0x1A"`, `"0777"`, `"1e3"` as hex, octal, or scientific notation | User input silently converted to unintended numeric value |
| **Boolean-to-Integer Coercion** | `true` becomes `1`, `false` becomes `0` in arithmetic contexts | Authorization checks where boolean result enters arithmetic |

**Example**: In PHP < 8.0, if a password's MD5 hash starts with `0e` followed by digits (e.g., `0e462097431906509019562988736854`), comparing it with `==` to any other `0e...` string returns `true`, because PHP evaluates both as `0.0`. This enables authentication bypass by finding a password whose hash has this format. CVE-2023-53894 exploited this exact pattern in phpfm 1.7.9 (note: CVE-2023-43154 is a separate loose comparison vulnerability in Macs Framework CMS 1.1.4f).

---

## §3. Floating-Point and Precision Errors

IEEE 754 floating-point numbers inherently cannot represent all real numbers exactly. The gaps between representable values, combined with rounding modes and special values, create an attack surface distinct from integer arithmetic.

### §3-1. Precision Loss and Rounding Errors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Representational Gap** | Values like 0.1 cannot be represented exactly in binary floating-point; `0.1 + 0.2 ≠ 0.3` | Financial calculations using float/double instead of fixed-point |
| **Accumulation Drift** | Small rounding errors compound over many operations, diverging from the mathematically correct result | Iterative calculations, running totals, interest computation |
| **Rounding Direction Exploitation** | Attacker crafts inputs that consistently round in their favor (e.g., always rounding down debits) | DeFi swap calculations, currency exchange, interest accrual |
| **Catastrophic Cancellation** | Subtracting two nearly-equal large numbers amplifies relative error | Scientific calculations, geometric comparisons |
| **Division Precision Loss** | Integer division in Solidity truncates toward zero; `1 / 3 * 3 = 0` instead of 1 | DeFi token exchange rate calculations, share pricing |

**Example**: The Balancer V2 exploit (November 2025) was caused by inconsistent rounding between upscale and downscale operations in batch swaps. When token amounts were pushed to specific rounding boundaries, Solidity's integer division caused precision loss that distorted BPT pricing, enabling repeated profitable swaps that drained pools across multiple chains.

### §3-2. Special Floating-Point Values

IEEE 754 defines special values (NaN, ±Infinity, ±0, denormals) with unique comparison and arithmetic behaviors that can bypass validation logic.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **NaN Bypass** | `NaN != NaN` is `true`; `NaN < x` and `NaN > x` are both `false`; NaN fails all ordering comparisons | Range check `if (value >= min && value <= max)` passes NaN through because both conditions are `false`, and the negation `!(value < min \|\| value > max)` evaluates to `true` |
| **Infinity Injection** | `Infinity * 0 = NaN`; `1 / Infinity = 0`; `Infinity + 1 = Infinity`; arithmetic with Infinity produces unexpected results | Division by user input without zero-check, or user directly supplies "Infinity" |
| **Negative Zero (-0)** | `-0 === 0` is `true` in JS, but `1/-0 = -Infinity` vs `1/0 = Infinity`; `-0` can bypass sign checks | Currency calculations, direction-dependent logic |
| **Denormalized Numbers** | Very small floating-point values near zero have reduced precision and can cause timing side channels | Cryptographic implementations, differential privacy |
| **Quiet vs Signaling NaN** | Signaling NaN triggers exceptions on use; quiet NaN propagates silently through calculations | Exception-based control flow, error handling logic |

**Example**: A price validation `if (price > 0 && price < 1000000)` can be bypassed by submitting `NaN` as the price — both comparisons return `false`, and if the guard is structured as `if (!(price <= 0 || price >= 1000000))`, NaN passes through because the inner disjunction is also `false`.

### §3-3. Floating-Point Architectural Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Floating Point Value Injection (FPVI)** | Transient execution attack exploiting FPU assist micro-ops; attacker controls NaN-boxed values to influence speculative execution (CVE-2021-0086) | JIT compiler using NaN boxing for dynamic types; speculative execution |
| **Lazy FP State Restore** | OS lazy-restores FPU registers on context switch; attacker process reads previous process's FP state, leaking AES keys (CVE-2018-3665) | Kernel using lazy FPU save/restore; cryptographic operations in FPU |
| **Timing Side Channel** | Denormalized float operations take longer, leaking information about values being processed | Differential privacy mechanisms, cryptographic constant-time guarantees |

---

## §4. Boundary Condition and Off-by-One Errors

Boundary condition errors occur at the edges of valid ranges — the first element, last element, empty case, maximum value, or minimum value. Off-by-one errors are the most common subtype, where a count, index, or limit is wrong by exactly one.

### §4-1. Index and Loop Boundary Errors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Fence-Post Error (Off-by-One)** | Loop iterates one time too many or too few; `for (i = 0; i <= n; i++)` processes n+1 elements when n was intended | Array/buffer iteration with `<=` instead of `<` |
| **Zero-Based vs One-Based Confusion** | Index 0 and index 1 confused between different components or APIs | Cross-language or cross-library boundaries |
| **Null Terminator Off-by-One** | `strncat` always appends a null terminator after copying up to `n` bytes, risking a write one byte past the allocated buffer. Conversely, `strncpy` does *not* null-terminate when the source length ≥ `n`, leaving an unterminated string — a distinct but related class of bug | String handling with manually calculated buffer sizes |
| **Inclusive vs Exclusive Range** | Range [start, end] vs [start, end) confusion; one extra or one fewer element processed | API contracts unclear about range inclusivity |
| **Empty Collection Edge Case** | Code assumes collection has at least one element; `array.length - 1` underflows when length is 0 | Unsigned arithmetic on `.length` or `.size()` |

**Example**: A classic null-terminator off-by-one: `strncat(buf, user_input, sizeof(buf) - strlen(buf))` can write one byte past `buf` because `strncat` adds a null terminator *after* copying the specified number of characters. On little-endian architectures, this overwrites the LSB of the caller's saved EBP, enabling EBP overwrite exploitation for arbitrary code execution.

### §4-2. Boundary Value Edge Cases

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Zero Value** | Division by zero, allocation of zero bytes, zero-length copy with undefined behavior | User-controllable denominators, lengths, or counts |
| **Maximum Type Value** | Input at `INT_MAX`, `UINT_MAX`, `SIZE_MAX` causes overflow on any addition | Edge-of-range input not explicitly tested |
| **Minimum Type Value** | `INT_MIN` negation overflows; `abs(INT_MIN)` is UB | Absolute value, negation without INT_MIN guard |
| **Power-of-Two Boundaries** | Values near 2^8, 2^16, 2^32, 2^64 trigger type-width-dependent behavior | Cross-platform code, serialization boundaries |
| **Allocation of Zero Bytes** | `malloc(0)` may return NULL or a unique pointer; subsequent operations on either case may crash or corrupt | User controls allocation size that reaches zero after arithmetic |

### §4-3. Comparison and Ordering Edge Cases

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Strict vs Non-Strict Inequality** | `<` vs `<=` in access control, pagination, or rate-limiting creates one-unit gap | Off-by-one in "maximum attempts" or "page count" |
| **Equality on Floating-Point** | `if (a == b)` on floats fails due to precision; attacker exploits the gap | Price matching, balance verification using float equality |
| **Unsigned Comparison with Zero** | `if (unsigned_val >= 0)` is always true (tautology); compiler may warn but code ships | Intended as lower-bound validation but is vacuous |
| **Mixed-Type Comparison** | Comparing `int32` with `int64` may truncate or sign-extend unexpectedly | Cross-type comparison in security checks |

---

## §5. Allocation and Size Calculation Errors

These vulnerabilities occur when integer arithmetic errors propagate into memory allocation, causing the allocated buffer to be smaller than the data written to it. This is the primary bridge between numeric errors and memory corruption.

### §5-1. Multiplication Overflow in Allocation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **count × size Overflow** | `malloc(n * element_size)` where the product wraps around, allocating a tiny buffer | User controls `n` or `element_size` |
| **Dimension Product Overflow** | Image `width × height × bytes_per_pixel` overflows in image/video parsers | Untrusted media file with crafted dimensions |
| **Array-of-Structures Sizing** | `sizeof(struct) × count` wraps, then loop writes `count` full structures to undersized buffer | Deserialization of array with attacker-controlled count |

**Example**: CVE-2024-11477 (7-Zip Zstandard Decompression) — lack of proper validation of user-supplied data results in an integer underflow before writing to memory, enabling remote code execution via a crafted archive file.

### §5-2. Addition Overflow in Size Calculation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Header + Payload Overflow** | `malloc(header_len + payload_len)` wraps when both are large | Network protocol parser, file format parser |
| **Alignment Padding Overflow** | `size + alignment_pad` wraps when size is near MAX | Memory allocator alignment logic |
| **Null-Terminator Addition** | `malloc(strlen(input) + 1)` wraps if `strlen` returns `SIZE_MAX` | Extremely long input strings (unlikely but possible on 32-bit) |

### §5-3. Subtraction Underflow in Length Calculation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Remaining Length Underflow** | `total_len - consumed` underflows when consumed > total_len, producing enormous `remaining` | Incremental parsing without cumulative bounds check |
| **Buffer Offset Subtraction** | `buf_end - current_pos` underflows if `current_pos` advanced past `buf_end` | Pointer arithmetic without bounds verification |

**Example**: CVE-2024-37079 (VMware vCenter Server) — a heap-overflow vulnerability in the DCERPC protocol implementation enabled arbitrary code execution. NVD/Broadcom advisories describe the root cause as a heap-overflow; specific internal mechanics (e.g., whether triggered by integer underflow in size calculation) are not detailed in public advisories.

---

## §6. Numeric String Parsing and Format Confusion

These vulnerabilities exploit the many ways a numeric value can be represented as a string, and the inconsistencies between how different parsers interpret these representations.

### §6-1. Radix and Notation Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Hexadecimal Interpretation** | `"0xFF"` parsed as 255 instead of an error or literal string | `parseInt("0xFF")` without explicit radix, or IP address parser |
| **Octal Interpretation** | `"0777"` parsed as 511 (octal) instead of 777 (decimal); or leading zeros treated differently across parsers | Older JavaScript engines, C `strtol` without base, file permission handlers |
| **Scientific Notation** | `"1e3"` parsed as 1000; `"1e-7"` as 0.0000001; `"5e-7"` via `parseInt` returns just 5 | Input validation expects decimal digits but parser accepts exponential |
| **Binary/Custom Radix** | `"0b1010"` parsed as 10; `parseInt("10", 36)` returns 36 | Exotic radix support in language builtins |

### §6-2. Numeric String Edge Cases

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Leading/Trailing Whitespace** | `" 42 "` parsed as 42 with silent whitespace stripping | Validator checks string format but parser is more lenient |
| **Partial Parse** | `parseInt("42abc")` returns 42, ignoring `"abc"` | Injection of non-numeric suffix after numeric prefix |
| **Plus Sign Prefix** | `"+42"` may or may not be accepted as valid numeric input | Inconsistent acceptance between validator and parser |
| **Multiple Decimal Points** | `"1.2.3"` behavior varies: error, parse as 1.2, or NaN | Format validation mismatch |
| **Unicode Digits** | Fullwidth digits (U+FF10–U+FF19), Arabic-Indic digits, or other Unicode numerals may be accepted or rejected | Internationalized applications, WAF bypass |
| **Comma vs Period Decimal** | `"1,234.56"` vs `"1.234,56"` locale-dependent interpretation | Internationalized financial applications |

### §6-3. Numeric Format Bypass in Security Contexts

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IP Address Numeric Forms** | `0x7f000001`, `2130706433`, `017700000001` (octal) all represent `127.0.0.1` | SSRF blocklist checking decimal-dotted notation only |
| **Numeric Encoding in SQL** | `0x61646D696E` used instead of `'admin'` to bypass WAF string matching | WAF rule matching string literals but not hex-encoded equivalents |
| **JSON Numeric Precision** | JSON number `9999999999999999999` may be parsed as different values by different backends | Distributed systems with heterogeneous JSON parsers |
| **YAML Numeric Interpretation** | `on`/`off`, `yes`/`no` parsed as boolean 1/0; `0777` as octal; `1_000` with underscores | Configuration injection via YAML type coercion |

---

## §7. Business Logic Numeric Manipulation

These vulnerabilities exploit application-layer numeric assumptions — prices, quantities, balances, discounts, limits, and rates — rather than machine-level representation errors. They are typically undetectable by automated scanners.

### §7-1. Price and Quantity Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Negative Price/Quantity** | Submitting quantity `-1` or price `-100` causes server to calculate negative total, crediting the attacker | Server-side validation missing for negative values |
| **Zero Price** | Setting item price to `0` or `0.00` in intercepted request | Price transmitted client-side rather than looked up server-side |
| **Fractional Quantity** | Ordering `0.001` units of an item priced per-unit to exploit rounding | Integer quantity assumed but float accepted |
| **Extreme Quantity** | Ordering `99999999` units to trigger overflow in total calculation or inventory underflow | No upper bound on quantity, total calculated client-side |
| **Price Parameter Tampering** | Modifying price field in hidden form field, cookie, or API request parameter | Price stored in client-controlled state |

### §7-2. Discount and Coupon Logic

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Negative Discount** | Applying a discount value of `-50%` to increase price/credit | Discount value accepted from client without validation |
| **Stacking Beyond 100%** | Applying multiple 30% discounts to exceed 100% total discount, making the total negative | No cap on cumulative discount percentage |
| **Coupon Race Condition** | Redeeming same single-use coupon concurrently via parallel requests | TOCTOU between "check if used" and "mark as used" (§8-1) |
| **Discount on Discount** | 50% discount applied after 50% discount = 75% off instead of expected 50% | Percentage discounts applied sequentially to reduced price |

### §7-3. Balance and Financial Logic

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Negative Transfer Amount** | Transferring `-$100` reverses flow direction, extracting funds from recipient | Transfer amount not validated as strictly positive |
| **Rounding Exploitation (Salami Attack)** | Accumulating fractional cents from many rounding operations into attacker's account | Rounding applied per-transaction without reconciliation |
| **Currency Precision Mismatch** | Exploiting different decimal precision between currencies (JPY has 0 decimals, BTC has 8) during exchange | Currency conversion without precision normalization |
| **Minimum/Maximum Bypass** | Transaction just below reporting threshold, or amount just above minimum withdrawal to drain via many small transactions | Threshold-based logic without aggregate tracking |
| **Integer Division in Share Calculation** | `shares = deposit / price_per_share` truncates in integer math; when `price_per_share > deposit`, shares = 0 but deposit is consumed | DeFi vault share minting, dividend distribution |

**Example**: The OnyxProtocol exploit (November 2023) exploited precision loss in share-to-asset conversion: by donating assets to inflate the share price and then exploiting integer division truncation, the attacker extracted more value than deposited.

### §7-4. Rate and Limit Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Rate Counter Overflow** | Rate limit counter wraps from MAX to 0, resetting the limit | Counter stored in a type too small for actual request volume |
| **Batch Size Manipulation** | Setting batch size to 0 or negative bypasses per-item rate limiting | Batch processing divides quota by batch size |
| **Time Window Boundary** | Sending requests at the exact boundary of rate-limit time windows to get 2× the allowed rate | Time window checked with `<` instead of `<=` or vice versa |

---

## §8. Temporal and Concurrency-Driven Numeric Errors

These vulnerabilities exploit the window between checking a numeric value and using it (TOCTOU), or the absence of atomic operations on numeric state under concurrent access.

### §8-1. TOCTOU on Numeric State

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Balance Double-Spend** | Concurrent withdrawal requests both pass balance check before either debit is applied | Non-atomic check-then-debit pattern |
| **Inventory Over-Sell** | Concurrent purchase requests both see `stock >= 1` before either decrements stock to 0 | Database read-then-update without row-level locking |
| **Vote/Rating Inflation** | Concurrent requests each pass "user hasn't voted" check before any vote is recorded | Non-atomic read-then-write on vote counter |
| **Limit Bypass via Parallelism** | Multiple concurrent requests all pass limit check before any increments the counter | Rate limiter uses non-atomic check-and-increment |

**Example**: In a banking application, two concurrent transfer-$500 requests from a $600 account both pass the `if (balance >= amount)` check (both see $600), then both debit $500, resulting in a -$400 balance. The attack requires precise timing, achievable via HTTP/2 single-packet technique or last-byte synchronization.

### §8-2. Non-Atomic Compound Numeric Operations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Read-Modify-Write Race** | Two threads read same counter, increment locally, write back — one increment lost | Shared counter without mutex or atomic operation |
| **Check-Then-Act on Computed Value** | Value derived from multiple reads; between reads, underlying data changes | Derived value (e.g., total = sum of items) computed non-atomically |
| **Phantom Read in Aggregation** | SUM/COUNT query returns stale value because underlying rows are being modified concurrently | Database isolation level below SERIALIZABLE |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Memory Corruption (Heap/Stack Overflow)** | C/C++ native code, kernel modules, media parsers | §1 + §2 + §4-1 + §5 |
| **Authentication/Authorization Bypass** | PHP/JS web applications, JWT validation | §2-3 + §3-2 + §6-3 |
| **Financial Manipulation** | E-commerce, banking, payment gateways | §7-1 + §7-2 + §7-3 + §3-1 |
| **Smart Contract Exploitation** | Solidity/EVM, DeFi protocols | §1-1 + §1-2 + §3-1 + §7-3 |
| **Denial of Service** | Any system processing untrusted numeric input | §1 + §3-2 + §4-2 + §5 |
| **Privilege Escalation** | OS kernels, drivers, setuid binaries | §1-3 + §2-1 + §2-2 + §5 |
| **Data Corruption/Exfiltration** | Cross-language serialization, API gateways | §2-2 + §3-3 + §6-3 |
| **Double-Spend / Resource Theft** | Concurrent web apps, distributed financial systems | §8-1 + §8-2 + §7-2 |
| **SSRF / Filter Bypass** | Web applications with IP/URL validation | §6-1 + §6-3 |
| **Cryptographic Key Leakage** | OS schedulers, speculative execution | §3-3 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 (unsigned overflow — multiplication) | BEC Token (CVE-2018-10299) | Large notional loss; Ethereum ERC-20 `batchTransfer` multiplication overflow (`value * cnt`) |
| §5-3 (heap overflow) | CVE-2024-37079 (VMware vCenter) | RCE via heap-overflow in DCERPC implementation (exact integer arithmetic root cause not detailed in public advisories) |
| §1-1 (unsigned overflow/wraparound) | CVE-2024-32972 (Go-Ethereum) | Integer overflow/wraparound (`count-1` → `UINT64_MAX`) in `handleGetBlockHeaders` ETH protocol handler |
| §1-2 (integer underflow) | CVE-2024-11477 (7-Zip Zstandard) | RCE via integer underflow before memory write in Zstandard decompression |
| §1-2 (subtraction underflow) | CVE-2024-47606 (GStreamer) | Code execution via integer underflow in qtdemux parser |
| §1-2 (integer underflow) | CVE-2024-0808 (Chrome WebUI) | Integer underflow in WebUI leading to heap corruption |
| §2-2 (truncation) | CVE-2025-49679 (Windows Shell) | Local privilege escalation to SYSTEM (CVSS 7.8) |
| §3-1 (rounding direction) | Balancer V2 (Nov 2025) | Balancer's post-mortem attributes the Composable Stable Pool exploit to incorrect rounding in the exact-output swap path; Balancer-deployed pools lost an estimated $94.8 million |
| §3-1 (precision loss) | OnyxProtocol (Nov 2023) | Precision loss in share calculation |
| §2-3 (PHP type juggling) | CVE-2023-53894 (phpfm 1.7.9) | Authentication bypass via 0e magic hash type juggling (CVE-2023-43154 is Macs Framework CMS 1.1.4f) |
| §2-1 (signedness) | CVE-2020-4032 (FreeRDP) | OOB read via signed-to-unsigned conversion of negative diff |
| §3-3 (FP architectural) | CVE-2021-0086 (FPVI) | Transient execution attack via NaN-boxed values (CVSS 6.5) |
| §3-3 (FP state leak) | CVE-2018-3665 (LazyFP) | Cryptographic key leakage via FPU register state disclosure |
| §7-2 (coupon race) | Stripe coupon bug (HackerOne) | Unlimited discount redemption via parallel coupon reuse |
| §7-3 (precision) | DeFi overflow/underflow bugs | Common Immunefi submission class; bounty ranges vary by program and impact |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **UBSan (Clang/GCC)** | C/C++ undefined behavior including signed overflow | Runtime instrumentation that traps on UB; `-fsanitize=undefined,integer` |
| **ASan + UBSan** | Integer overflow → buffer overflow chains in C/C++ | Combines memory error detection with integer overflow detection |
| **AFL++ / libFuzzer** | Any native code accepting numeric input | Coverage-guided fuzzing with dictionaries targeting boundary values |
| **SwordFuzzer** | Integer overflow in binary programs | Smart fuzzing with online dynamic taint analysis targeting arithmetic operations |
| **ELAID** | Integer-overflow-to-buffer-overflow (IO2BO) chains | Static analysis via inter-procedural call graph + taint analysis |
| **Slither** | Solidity smart contracts | Static analysis for overflow, underflow, precision loss, unchecked arithmetic |
| **Mythril** | Solidity smart contracts | Symbolic execution for integer overflow/underflow, constraint solving |
| **Semgrep** | Multi-language (PHP, JS, Python, Java) | Pattern-based static analysis for type juggling, unsafe comparisons, numeric validation gaps |
| **Burp Suite Intruder** | Web application business logic | Numeric boundary fuzzing with payloads: 0, -1, MAX_INT, NaN, Infinity |
| **DeFort** | DeFi smart contracts | Automated detection and analysis of price manipulation attacks |
| **-Wconversion / -Wsign-conversion** | C/C++ compilation | Compiler warnings for implicit type conversion and signedness issues |
| **safenum (JavaScript)** | JavaScript numeric parsing | Safe replacements for `parseInt` / `parseFloat` with strict validation |
| **PHPStan / Psalm** | PHP type safety | Static analysis detecting loose comparison operators and type confusion |

---

## References

- [CWE-189: Numeric Errors](https://cwe.mitre.org/data/definitions/189.html)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-191: Integer Underflow](https://cwe.mitre.org/data/definitions/191.html)
- [CWE-192: Integer Coercion Error](https://cwe.mitre.org/data/definitions/192.html)
- [CWE-193: Off-by-one Error](https://cwe.mitre.org/data/definitions/193.html)
- [CWE-195: Signed to Unsigned Conversion Error](https://cwe.mitre.org/data/definitions/195.html)
- [CWE-197: Numeric Truncation Error](https://cwe.mitre.org/data/definitions/197.html)
- [CWE-681: Incorrect Conversion between Numeric Types](https://cwe.mitre.org/data/definitions/681.html)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP Smart Contract Top 10 (2025): SC08 Integer Overflow/Underflow](https://github.com/OWASP/www-project-smart-contract-top-10/blob/main/2025/en/src/SC08-integer-overflow-underflow.md)
- IEEE 754-2019: Standard for Floating-Point Arithmetic
- [2024 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [Intel — Floating Point Value Injection / CVE-2021-0086 / INTEL-SA-00516](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/floating-point-value-injection.html)
- [Balancer — November 3, 2025 exploit post-mortem](https://medium.com/balancer-protocol/nov-3-exploit-post-mortem-51dcbeb6b020)
