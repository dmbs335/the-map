# Web Race Condition Mutation/Variation Taxonomy

---

## Classification Structure

Web race conditions arise when an application processes concurrent requests against shared state without adequate synchronization, creating a window between a **check** (reading state) and a **use** (modifying state) — the classic Time-of-Check to Time-of-Use (TOCTOU) pattern. Unlike traditional concurrency bugs that manifest as crashes or corruption, web race conditions are **weaponizable**: attackers deliberately engineer collisions to violate business logic invariants, bypass security controls, or escalate privileges.

This taxonomy organizes the full mutation space along three axes:

- **Axis 1 — Mutation Target (Primary)**: The structural component of application state being raced. This determines *what* is attacked — resource counters, authentication state, object construction pipelines, data routing bindings, database transactions, filesystem operations, temporal tokens, or distributed/asynchronous processing. Each top-level section (§1–§8) corresponds to one target category.

- **Axis 2 — Race Window Type (Cross-cutting)**: The synchronization technique used to create the collision. This determines *how* the race is triggered — the delivery mechanism that ensures concurrent arrival at the server.

- **Axis 3 — Attack Scenario (Mapping)**: The real-world exploitation context — *where* the race condition is weaponized for business impact.

### Axis 2 Summary: Race Window Synchronization Techniques

| Technique | Protocol | Mechanism | Precision | Capacity |
|-----------|----------|-----------|-----------|----------|
| **Single-Packet Attack** | HTTP/2 | Multiplex 20–30 complete requests into one TCP packet by withholding final frames, then flushing together | ~1ms median spread, σ=0.3ms | 20–30 requests per packet |
| **First-Sequence Sync** | HTTP/2 | IP fragmentation + TCP sequence reordering to deliver up to 65,535 bytes atomically; bypasses 1,500-byte MTU limit | ~16μs per request | ~10,000 requests in 166ms |
| **Last-Byte Sync** | HTTP/1.1 | Send all request bytes except the final byte across multiple connections, then release all final bytes simultaneously | ~4ms median spread, σ=3ms | Limited by connection count |
| **HTTP/3 QUIC Last-Frame Sync** | HTTP/3 | Coalesce multiple QUIC stream-final DATA frames (FIN) into a single UDP datagram | Sub-millisecond (implementation-dependent) | Bounded by `max_streams` transport parameter |
| **Connection Warming** | Any | Send inconsequential pre-requests to normalize server-side routing and processing latency before the attack salvo | Technique amplifier (not standalone) | N/A |
| **Deferred/Async Collision** | Any | Exploit asynchronous backend processing (batch jobs, email queues, event-driven pipelines) where requests separated by minutes/hours collide during deferred execution | Variable (seconds to hours) | Typically 2 requests |
| **Database-Level** | N/A | Exploit insufficient transaction isolation (Read Committed default) allowing concurrent SELECTs to read identical stale values before any write lock activates | Depends on isolation level + server load | Transaction-bounded |
| **Filesystem-Level** | N/A | Symlink swap or file replacement during the window between path validation and file I/O operation | Microseconds to milliseconds | Single operation pair |

### Axis 3 Summary: Attack Scenarios

| Scenario | Description | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Limit Bypass / Double-Spend** | Exceed counters, quotas, balances, or rate limits | §1 + §5 |
| **Authentication Bypass** | Circumvent login, MFA, email verification, or session controls | §2 + §3 |
| **Privilege Escalation** | Gain elevated roles, access unauthorized resources | §2 + §4 |
| **Account Takeover** | Hijack accounts via token misrouting or email confusion | §4 |
| **Remote Code Execution** | Achieve code execution via file overwrite or compilation races | §6 |
| **Cache Poisoning** | Contaminate cache with attacker-controlled content via race windows | §8 |
| **Data Corruption** | Corrupt business data through unsynchronized concurrent writes | §5 + §8 |
| **Denial of Service** | Exhaust resources or create deadlocks through concurrent operations | §1 + §5 |

---

## §1. Resource Limit State Races

Resource limit races target the gap between **checking** a counter/quota/balance and **updating** it. When multiple concurrent requests pass the check before any of them reaches the update, each request proceeds as if the limit has not been reached — resulting in over-consumption beyond the intended constraint.

### §1-1. Financial Balance Overdraw

The most direct form: concurrent withdrawal/transfer/purchase requests that each read the same pre-deduction balance, pass the sufficiency check, and then each deduct independently.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct balance overdraw** | N concurrent requests each read `balance >= amount`, then each executes `balance -= amount` | Non-serializable database isolation (§5) or application-side calculation |
| **Gift card double-redeem** | Concurrent redemption requests for a single-use gift card each verify `card.redeemed == false` before any sets it to `true` | No database-level uniqueness constraint on redemption |
| **Funds transfer duplication** | Simultaneous transfers from the same source account each read the same available balance | Application performs read-then-write instead of atomic `UPDATE ... WHERE balance >= amount` |
| **Cryptocurrency double-spend** | Multiple withdrawal requests submitted before blockchain/ledger confirmation | Reliance on pending status without locking |

**Example payload pattern**: Send 50 identical `POST /api/withdraw` requests via single-packet attack; if 5 succeed instead of 1, the account balance goes negative.

### §1-2. Coupon / Discount Code Abuse

Applications that enforce single-use or limited-use promotional codes are vulnerable when the "has this code been used?" check and the "mark as used" write are not atomic.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Single-use code multi-redemption** | Concurrent `POST /apply-coupon` requests each verify `coupon.used == false`, all pass, then each marks it as used independently | Check and update in separate database operations |
| **Per-user limit bypass** | Each request verifies `user_usage_count < max_uses` before incrementing; concurrent requests all read the same count | Counter increment not locked or atomic |
| **Stacking beyond cap** | Multiple requests apply different (or same) coupon codes simultaneously, bypassing the "one coupon per order" constraint | Cart-level validation not serialized |
| **Promotional window race** | Submit redemption requests at the exact boundary of a promotion's expiry, exploiting the gap between time-check and code-validation | Separate timestamp check and business logic |

### §1-3. Rate Limit and Anti-Automation Bypass

Rate limiters that count requests and block after a threshold can be bypassed if the counter increment is not atomic with request processing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Brute-force amplification** | Send N password attempts in a single packet; all are processed before the rate counter increments | Rate counter checked/incremented per-request without locking |
| **CAPTCHA solution reuse** | Submit the same solved CAPTCHA token across concurrent requests; each validates against the same "unused" state | CAPTCHA invalidation not atomic with verification |
| **API quota bypass** | Concurrent API calls each check `calls_today < limit` before any increments the counter | Quota enforcement at application layer with Read Committed isolation |
| **Vote/rating inflation** | Multiple concurrent votes from the same user each pass the "has user voted?" check | Uniqueness constraint only at application level, not database level |

### §1-4. Inventory and Stock Races

E-commerce and booking systems where available quantity is checked and decremented as separate operations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Overselling** | Concurrent purchase requests each verify `stock > 0` and proceed; all decrement independently | Stock check and decrement not in serializable transaction |
| **Seat/reservation double-booking** | Multiple concurrent booking requests for the same resource (seat, room, timeslot) each find it "available" | No exclusive lock on the resource during booking |
| **Cart manipulation during checkout** | Add items to cart concurrently with checkout completion; items added after payment calculation but before inventory deduction | Cart state not frozen during payment processing |

---

## §2. Authentication and Session State Races

Authentication flows involve multi-step state transitions (credential verification → session creation → privilege assignment → MFA enforcement). Race conditions in these transitions can bypass entire security controls.

### §2-1. Login and Credential Verification

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Concurrent login bypass** | Multiple login requests with incorrect credentials submitted simultaneously; the rate-limit/lockout counter fails to increment atomically, allowing more attempts than permitted | Account lockout logic uses non-atomic counter |
| **Session creation race** | Login endpoint creates session before fully validating credentials; concurrent request accesses the pre-validation session | Session token issued before authentication completes |
| **Password check TOCTOU** | Concurrent password change and login requests; login validates old password while change is in progress, then session persists with new password | Password read and session binding not atomic |

### §2-2. Multi-Factor Authentication Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **2FA window bypass** | After primary authentication, a brief window exists before MFA is enforced; concurrent request to a protected endpoint during this window bypasses MFA | Session elevated to "authenticated" before MFA challenge completes |
| **OTP brute-force amplification** | Submit hundreds of OTP guesses in a single packet before the rate limiter or attempt counter activates (cross-reference §1-3) | OTP validation endpoint rate-limited at application layer |
| **MFA status race** | Simultaneously submit correct MFA code and request to MFA-protected resource; the resource request arrives before MFA status is written | MFA verification and session flag update are separate operations |

### §2-3. OAuth and Token Lifecycle

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Authorization code multi-exchange** | Exchange a single OAuth authorization code for multiple access/refresh token pairs by submitting concurrent `POST /token` requests | Authorization code invalidation not atomic with token issuance |
| **Refresh token race** | Multiple services/threads attempt to refresh the same token simultaneously; one gets a valid new pair while others either fail or create duplicate valid pairs | Token rotation not serialized; old refresh token not immediately invalidated |
| **Token revocation race** | Revoke access while concurrently using the access token; the API call completes before revocation propagates | Revocation is eventually consistent, not immediately enforced |
| **Permanent token persistence** | Race between authorization code exchange and code invalidation creates token pairs that persist even after user revokes application access | Token issuance and code deletion not in same transaction |

### §2-4. Session Binding and Fixation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session privilege escalation** | Concurrent requests where one changes session privilege level while another reads the pre-change state | Session state modified without exclusive lock |
| **Cross-user session collision** | Under high concurrency, session assignment logic races and assigns one user's session to another | Session ID generation or binding not thread-safe |
| **Remember-me token duplication** | Concurrent login requests with "remember me" flag generate duplicate persistent tokens, one of which survives logout | Token generation not deduplicated per-session |

---

## §3. Object Construction State Races (Partial Construction)

When applications create objects through multiple sequential operations (INSERT user → SET api_key → SET permissions), a window exists where the object is in an **incomplete but queryable** state. Attackers race to access the object during this partial construction window.

### §3-1. Uninitialized Field Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Null/empty credential bypass** | User record created with NULL password/API key; concurrent request authenticates against this NULL value by sending empty/null input | Application compares input to uninitialized field; frameworks that cast empty arrays to null (PHP `param[]=`) |
| **Default role exploitation** | User created with default elevated role before explicit role assignment demotes them; concurrent request during this window inherits elevated privileges | Role assignment is a separate operation from user creation |
| **Uninitialized token match** | Registration creates user with empty confirmation token; concurrent confirmation request with empty token (`token=` or `token[]=`) matches the uninitialized value | Token comparison treats NULL/empty as valid match |

**Example**: Register user via `POST /register`, then immediately flood `POST /confirm?token[]=` — PHP's `[]` syntax produces an empty array, which may match an uninitialized database value through loose comparison.

### §3-2. Multi-Step Object Assembly

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Permission-before-restriction** | Object created with full permissions, then restrictions applied in subsequent operation; access during the gap yields unrestricted access | Additive creation (start open, then restrict) rather than restrictive creation (start locked, then open) |
| **Profile completion race** | User profile created in database, then profile fields populated; concurrent access to incomplete profile reveals default/sensitive data | Profile accessible before construction completes |
| **API key pre-assignment access** | Object queryable before its API key is assigned; concurrent request generates or reads the pre-assignment state | Sequential INSERT + UPDATE instead of single INSERT with all fields |

### §3-3. Object Masking and Duplication

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate object creation** | Concurrent creation requests bypass uniqueness checks, creating multiple objects where only one should exist (e.g., duplicate user invitations) | Uniqueness enforced at application layer, not database constraint |
| **Low-privilege placeholder masking** | Create a low-privilege duplicate of an object, then race a high-privilege creation to replace it; the low-privilege version may survive in some contexts | Object identity tied to mutable attribute (email, name) rather than immutable ID |

---

## §4. Data Binding and Routing State Races

These races exploit the gap between **where data is routed** (email sent, token delivered) and **what identity it binds to**. Multi-endpoint and single-endpoint collisions fall primarily into this category.

### §4-1. Multi-Endpoint Token Misrouting

The canonical multi-endpoint race: two different endpoints operating on the same underlying object are triggered simultaneously, causing security tokens to be routed to the wrong recipient.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Email change + verification race** | Simultaneously request email change to attacker-controlled address and trigger verification of the original address; verification token routes to original but binds to new address | Email change and verification are separate endpoints sharing the same user object |
| **Password reset + email change** | Initiate password reset (sends token to current email), then simultaneously change email; token arrives at old address but may reset password for the new-email account | Reset token bound to user ID, not to the email address at time of generation |
| **Invitation + permission change** | Send invitation to user while simultaneously changing their permission level; invitation may carry the pre-change or post-change permission level | Permission reads not serialized with invitation generation |

**Alignment technique**: When endpoints have different processing times, introduce client-side delays (e.g., 90ms) on the faster request to align race windows. Alternatively, trigger rate limits on the faster endpoint to artificially slow it.

### §4-2. Single-Endpoint Sub-State Collisions

A single endpoint internally transitions through multiple sub-states during processing; concurrent requests to the same endpoint with different input values create collisions between these sub-states.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Email address confusion** | Submit two email-change requests simultaneously with different addresses; confirmation sent to address A but link generated from address B (database read vs. parameter) | Endpoint reads email from database template at a different time than it uses the parameter for sending |
| **Concurrent parameter overwrite** | Two requests with different parameter values hit the same endpoint; the first request's read phase uses value A but the write phase uses value B (from the second request) | Shared mutable state between concurrent request handlers |
| **Background thread race** | Request triggers a background operation (email send, webhook, notification); second request modifies the data before the background thread reads it | Background processing reads state asynchronously after HTTP response |

### §4-3. Token-Identity Binding Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Token reuse across identity change** | Token generated for user A; user changes identifying attribute (email, username); token remains valid but now maps to the changed identity | Token bound to mutable attribute, not immutable user ID |
| **Verification token multi-use** | Submit the same one-time verification token concurrently; multiple requests succeed before the token is invalidated | Token invalidation not atomic with verification |
| **Cross-account token collision** | Two users trigger token generation simultaneously; predictable or timestamp-based token generation produces identical tokens (cross-reference §7) | Token generation uses low-entropy or time-dependent seed |

---

## §5. Database Transaction State Races

The database layer is the ultimate arbiter of state consistency — but most applications rely on default isolation levels that **do not prevent** race conditions. This category examines how database transaction semantics create or prevent exploitable race windows.

### §5-1. Isolation Level Gaps

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Read Committed overdraw** | Default isolation in most databases (PostgreSQL, MySQL, Oracle). Concurrent transactions each SELECT the same stale balance, pass the check, then each UPDATE independently | Application uses `SELECT balance; ... UPDATE SET balance = balance - amount` pattern |
| **Repeatable Read bypass (MySQL/MariaDB)** | MySQL's Repeatable Read does NOT use true Snapshot Isolation; phantom reads remain possible, allowing race conditions that PostgreSQL's Repeatable Read prevents | MySQL/MariaDB-specific behavior; PostgreSQL is safe at this level |
| **Non-repeatable read exploitation** | Between two reads within the same transaction, another transaction modifies the data; the second read sees different values, causing inconsistent logic | Read Committed isolation without explicit locking |
| **Application-side calculation race** | Application reads value into memory variable, performs calculation, writes back; concurrent transaction does the same with the same initial value | Business logic performed in application code rather than database (`UPDATE SET balance = balance - X`) |

**Database-specific vulnerability matrix**:

| Database | Read Uncommitted | Read Committed | Repeatable Read | Serializable |
|----------|-----------------|----------------|-----------------|--------------|
| **MySQL** | Vulnerable | Vulnerable | Vulnerable | Safe |
| **PostgreSQL** | Vulnerable | Vulnerable | Safe (Snapshot Isolation) | Safe |
| **MariaDB** | Vulnerable | Vulnerable | Vulnerable | Safe |

### §5-2. Locking Mechanism Failures

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing SELECT FOR UPDATE** | Application reads data without acquiring a row lock, then makes a decision and writes; concurrent transaction reads the same unlocked row | Developer assumes transaction isolation is sufficient without explicit locking |
| **Lock scope mismatch** | Lock acquired on one table but the race condition spans multiple tables; concurrent transaction modifies the unlocked table | Multi-table business logic with incomplete locking strategy |
| **Optimistic locking bypass** | Version column checked during UPDATE (`WHERE version = N`); attacker sends enough concurrent requests that statistical probability produces a success despite version conflicts | High-concurrency environments where optimistic locking relies on low collision probability |
| **Advisory lock race** | Application uses advisory locks but the lock acquisition itself is not atomic with the resource check | Lock-check-use pattern where check and lock are separate operations |

### §5-3. ORM and Framework-Level Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ORM read-modify-write** | ORM loads object into memory, application modifies fields, ORM writes back; concurrent request loads same object before write | Standard ORM pattern without explicit row locking (`Model.find()` → modify → `Model.save()`) |
| **Lazy loading race** | ORM lazily loads a related object; between the check and the load, another transaction modifies the relationship | Deferred/lazy loading in ORMs like Hibernate, Django ORM, ActiveRecord |
| **Counter cache invalidation** | Framework maintains a cached counter (e.g., Rails `counter_cache`); concurrent operations each increment the counter based on stale cached value | Counter updated via `UPDATE SET count = count + 1` but the framework reads the old value for validation |

---

## §6. Filesystem State Races

Filesystem TOCTOU races occur when the application validates a file path/property and then performs an operation on it, with an attacker modifying the filesystem between these two steps.

### §6-1. Symlink Substitution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Upload path symlink redirect** | Application validates upload destination is within allowed directory, then writes file; attacker replaces destination with a symlink to a sensitive location during the window | Upload directory writable by attacker; no `O_NOFOLLOW` flag |
| **Lock file symlink** | Application checks if lock file exists, then creates it; attacker creates symlink at lock file path pointing to victim file, causing truncation | Lock creation uses `open()` with `O_TRUNC` without `O_CREAT\|O_EXCL` |
| **Temporary file hijack** | Application creates temp file, writes sensitive data, then sets permissions; attacker pre-creates symlink at predicted temp path | Predictable temp file naming; no atomic create-and-set-permissions |

### §6-2. File Content Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSP/script compilation race** | Web server checks if source file has changed, then compiles it; attacker replaces the file between check and compilation (Apache Tomcat CVE-2024-50379/56337) | Case-insensitive filesystem (Windows); JSP compilation reads file twice |
| **Configuration file TOCTOU** | Application reads config file, validates contents, then re-reads for actual use; file modified between reads | Config file in a directory writable by attacker |
| **Upload-then-process race** | File uploaded, validated (e.g., image format check), then processed (e.g., served, executed); attacker replaces valid file with malicious one between validation and processing | File stored in accessible location before processing completes |

### §6-3. Directory Traversal via Race

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rename-based path escape** | Application validates that extracted archive entry is within target directory, then extracts; concurrent rename of parent directory changes the resolved path | Archive extraction with concurrent filesystem modification |
| **Mount point swap** | Application validates path on one filesystem, then accesses it; attacker unmounts/remounts different filesystem at that path | Attacker has mount privileges; containerized environments |

---

## §7. Temporal and Predictive State Races (Time-Sensitive Attacks)

When applications use timestamps or predictable values as security tokens, concurrent requests can generate **identical** tokens — or attackers can predict tokens by observing timing patterns.

### §7-1. Timestamp-Based Token Collision

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Identical reset token generation** | Two concurrent password reset requests generate tokens using the same timestamp seed, producing identical tokens; attacker's request yields the same token as victim's | Token generation uses `time()`, `Date.now()`, or similar low-resolution timestamp |
| **Predictable session ID** | Session IDs derived from timestamp + sequential counter; concurrent requests allow attacker to determine the range of possible victim session IDs | Session ID generation incorporates time-based component |
| **Nonce collision** | Security nonces (CSRF tokens, API nonces) generated from timestamps collide when requests arrive within the same time quantum | Nonce generation uses timestamp without sufficient additional entropy |

### §7-2. Timing Oracle Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Response time differential** | Measure processing time differences to determine whether a check passed or failed (e.g., valid username takes longer due to password hash comparison) | Not constant-time comparison; observable via single-packet attack precision |
| **Database timing side-channel** | Craft queries via ORM that cause observable processing delays when certain conditions are met (e.g., relational filtering in Prisma ORM) | ORM translates filter conditions to queries with data-dependent execution time |

---

## §8. Distributed and Asynchronous State Races

Modern architectures (microservices, serverless, event-driven) introduce race conditions that span service boundaries, message queues, and caching layers.

### §8-1. Microservice State Inconsistency

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-service eventual consistency** | Service A validates a constraint, then publishes an event; Service B processes the event and updates state; concurrent request to Service A arrives before B's state update propagates back | Eventual consistency between services; no distributed lock |
| **Saga pattern race** | Distributed transaction (saga) performs compensating actions on failure; concurrent request interacts with partially-compensated state | Compensation not atomic; intermediate states visible |
| **Service mesh routing race** | Load balancer routes concurrent requests to different service instances with unsynchronized local state | Stateful logic in stateless service instances; no shared state backend |

### §8-2. Event-Driven and Queue Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate event processing** | Same event delivered to multiple consumers or re-delivered due to acknowledgment timeout; each consumer processes it independently | Message queue at-least-once delivery without idempotency |
| **Out-of-order event processing** | Events published in order A→B, but consumer processes B before A, creating an inconsistent state | No event ordering guarantee; no sequence number validation |
| **Serverless cold-start race** | Multiple serverless function instances spin up for concurrent requests, each with independent state; no coordination between them | Serverless function performs state-dependent logic without external locking |

### §8-3. Cache-Level Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cache poisoning via race** | Concurrent request causes the cache to store attacker-influenced content (e.g., incomplete page, error response, different user's data) during a rendering race | Cache writes not serialized; first response to complete gets cached regardless of correctness |
| **Cache invalidation race** | Cache entry invalidated and re-populated; concurrent request reads stale cache between invalidation and repopulation | Non-atomic cache invalidation + repopulation |
| **Thundering herd** | Cache entry expires; N concurrent requests all miss cache and hit the backend simultaneously, each writing their result to cache | No cache stampede protection (locking, probabilistic expiry) |
| **Framework-level cache race (Next.js pattern)** | Race condition in framework-level caching (ISR, SSG) causes normal endpoints to serve internal data structures (pageProps) instead of rendered HTML | Framework caches intermediate representations; concurrent revalidation exposes them |

### §8-4. Deferred Collision Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Batch processing collision** | Two requests submitted hours apart both queue for asynchronous batch processing; they collide during batch execution, causing token/email misrouting | Backend uses batch/queue processing with shared mutable state |
| **Scheduled job race** | Scheduled cron job and incoming user request both modify the same resource simultaneously | No coordination between scheduled tasks and request processing |
| **Webhook delivery race** | Webhook fires and concurrent API request both update the same resource; webhook handler sees pre-update state | Webhook processing not serialized with API request handling |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Synchronization Technique |
|----------|-------------|---------------------------|--------------------------|
| **Double-Spend / Limit Bypass** | Monolith or microservice with shared DB | §1-1, §1-2, §1-4, §5-1 | Single-packet attack, First-sequence sync |
| **Authentication Bypass** | Any web application with multi-step auth | §2-1, §2-2, §3-1 | Single-packet attack |
| **Account Takeover** | Applications with email-based verification | §4-1, §4-2, §4-3 | Single-packet attack with connection warming |
| **OAuth Token Abuse** | OAuth 2.0 implementations | §2-3 | Single-packet attack |
| **Privilege Escalation** | RBAC systems, multi-tenant applications | §2-4, §3-1, §3-2 | Single-packet attack |
| **Remote Code Execution** | File upload, JSP/script compilation | §6-1, §6-2 | Filesystem-level race |
| **Cache Poisoning** | CDN/reverse proxy architectures, framework caching | §8-3 | Single-packet attack, Deferred collision |
| **Brute-Force Amplification** | Rate-limited endpoints | §1-3, §2-2 | Single-packet attack, First-sequence sync |
| **Data Corruption** | Distributed systems, event-driven architectures | §5-1, §8-1, §8-2 | Cross-service timing |
| **Financial Fraud** | Payment systems, e-commerce | §1-1, §1-2, §1-4, §5-1 | Single-packet attack |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §6-2 (JSP compilation race) + §6-1 (symlink) | CVE-2024-50379 / CVE-2024-56337 (Apache Tomcat) | CVSS 9.8. RCE via TOCTOU race in JSP compilation on case-insensitive filesystems (Windows). CVE-56337 is incomplete fix of CVE-50379 |
| §2-1 (signal handler race) | CVE-2024-6387 "regreSSHion" (OpenSSH) | Unauthenticated RCE via race condition in SIGALRM signal handler during LoginGraceTime. Affects sshd on glibc-based Linux |
| §1-1 (balance overdraw) + §5-1 | CVE-2024-58248 (nopCommerce) | Duplicate gift card redemption due to missing order placement locking |
| §8-3 (framework cache race) | CVE-2024-46982 (Next.js) | Cache poisoning via race condition in Pages Router; "Eclipse" technique bypasses original patch in Next.js 15.0.4 |
| §6-1 (symlink race in upload) | CVE-2025-67124 (Miniserve) | Arbitrary file overwrite outside document root via TOCTOU symlink race in upload finalization |
| §6-1 (symlink lock file) | CVE-2026-22701 / CVE-2025-68146 (Python filelock) | Arbitrary file truncation via symlink attack during lock file creation TOCTOU window |
| §6-1 (container runtime symlink) | CVE-2024-21626 (runC) | Container escape via file descriptor leak exploited through symlink, gaining host filesystem access |
| §1-2 (coupon multi-redemption) | HackerOne #157996 (Instacart) | Multiple coupon redemptions via concurrent requests |
| §2-3 (OAuth code multi-exchange) | HackerOne #55140 (OAuth2 implementations) | Multiple access/refresh token pairs from single authorization code |
| §1-2 (promo code bypass) | HackerOne #1717650 (Stripe) | Promotion code used more than once via race condition |
| §1-1 (gift card double-redeem) | HackerOne #759247 (Reverb.com) | Gift card redemption race allowing multiple uses |
| §4-1 (email verification race) | Multiple bounty programs, $1,000+ | Email change during verification causes tokens to route to different addresses |
| §8-1 (CI/CD TOCTOU) | Dependabot Core CI dispatch race | 19-second TOCTOU window in GitHub Actions workflow dispatch |
| §2-4 (session collision) | GitLab CVE-2022-4037 | Cross-user session assignment under concurrent authentication |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Repeater** (PortSwigger) | Multi/single-endpoint web races | "Send group in parallel" with native single-packet attack support for HTTP/2; connection warming via pre-requests |
| **Turbo Intruder** (PortSwigger, Burp Extension) | Advanced race condition exploitation | Jython scripting engine; `Engine.BURP2` for HTTP/2 single-packet, `Engine.THREADED` for HTTP/1.1; gating pattern (`gate='race1'` + `openGate()`) for synchronized delivery |
| **h2spacex** (Offensive Tool) | HTTP/2 single-packet attacks | Python/Scapy-based library for crafting low-level HTTP/2 single-packet race payloads |
| **RacePwn** (Offensive Tool) | General web race condition testing | Linux-based tool for high-concurrency race condition testing with configurable request patterns |
| **Race The Web** (Offensive Tool) | Race condition detection | Configurable multi-request tool that monitors for behavioral anomalies indicating race conditions |
| **Raceocat** (Offensive Tool) | Efficient race condition exploitation | Specialized tool for streamlined race condition exploitation workflows |
| **ffuf** (Fuzzer) | Concurrent endpoint testing | Go-based fast web fuzzer; useful for high-concurrency behavioral analysis |
| **Gato-X** (CI/CD Scanner) | GitHub Actions TOCTOU | Scans for workflow dispatch TOCTOU events and other GitHub Actions vulnerabilities |
| **OWASP ZAP + Custom Scripts** (Defensive/Offensive) | API race condition scanning | Automated scanning with custom scripts for concurrent request rate testing |
| **Semgrep** (SAST) | Database race condition patterns | Custom rules detecting missing isolation level specifications in transaction creation (e.g., Go/pgx patterns) |
| **db-race-conditions-playground** (Research) | Database isolation level testing | Playground environment for reproducing and testing database-layer race conditions across MySQL, PostgreSQL, MariaDB |
| **WS_RaceCondition_PoC** (Offensive Tool) | WebSocket race conditions | Java-based tool for parallel WebSocket message exploitation |
| **Burp WebSocket Turbo Intruder** (Burp Extension) | WebSocket races | THREADED engine for concurrent WebSocket frame delivery |

---

## Summary: Core Principles

**The fundamental property** that makes web race conditions possible is the **non-atomic composition of check-then-act operations across every layer of the web stack**. From JavaScript's single-threaded-but-async event loop, through multi-threaded application servers, to database engines with permissive default isolation levels, each layer independently handles concurrency — but the end-to-end composition of these layers creates emergent race windows that no single layer prevents. A request that appears atomic from the HTTP perspective (single endpoint, single response) may internally traverse multiple non-serialized steps: read a database value, make a business decision, write the result, send an email, update a cache, and publish an event — each step an opportunity for concurrent interference.

**Incremental patches fail** because race conditions are not point vulnerabilities in specific code; they are **structural properties of how state transitions are composed**. Fixing a coupon-redemption race by adding a uniqueness constraint addresses §1-2 but leaves §5-1 (database isolation) untouched. Setting the database to Serializable isolation eliminates §5-1 but has no effect on §6 (filesystem races), §8 (distributed races), or §4 (data routing races). Each fix addresses one intersection point in the mutation matrix while leaving dozens of others unprotected. Furthermore, modern architectural trends — microservices, serverless, event-driven systems, CDN caching — **expand** the race surface by introducing more asynchronous boundaries, more eventually-consistent state replicas, and more independent processing units that must be coordinated.

**A structural solution** requires defense-in-depth across all layers: (1) **atomic state transitions** at the database level using Serializable isolation or explicit `SELECT ... FOR UPDATE` locking for all business-critical operations; (2) **idempotency enforcement** at the API level through idempotency keys that prevent duplicate processing regardless of concurrent delivery; (3) **invariant enforcement via database constraints** (uniqueness, check constraints, foreign keys) as the ultimate backstop, independent of application logic; (4) **synchronization-aware architecture** where distributed systems use distributed locks, saga patterns with proper isolation, and exactly-once event processing. The single-packet attack and its successors (first-sequence sync, HTTP/3 last-frame sync) have made remote race conditions as reliable as local ones — the era of "this is too hard to exploit in practice" is definitively over.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### Research Papers & Conference Presentations

| # | Author / Organization | Title | URL | Year |
|---|---|---|---|---|
| 1 | James Kettle (PortSwigger) | Smashing the State Machine: The True Potential of Web Race Conditions | [PortSwigger Research](https://portswigger.net/research/smashing-the-state-machine) | 2023 |
| 2 | James Kettle (PortSwigger) | Smashing the State Machine (DEF CON 31 Presentation) | [DEF CON Media](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/James%20%27albinowax%27%20Kettle%20-%20Smashing%20the%20state%20machine%20the%20true%20potential%20of%20web%20race%20conditions.pdf) | 2023 |
| 3 | James Kettle (PortSwigger) | The Single-Packet Attack: Making Remote Race-Conditions 'Local' | [PortSwigger Research](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local) | 2023 |
| 4 | James Kettle (PortSwigger) | Turbo Intruder: Embracing the Billion-Request Attack | [PortSwigger Research](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) | 2019 |
| 5 | GMO Flatt Security | Beyond the Limit: Expanding Single-Packet Race Condition with First-Sequence Sync | [Flatt Security Research](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/) | 2024 |
| 6 | Viktor Chuchurski (Doyensec) | A Race to the Bottom — Database Transactions Undermining Your AppSec (OWASP Global AppSec Lisbon 2024) | [Doyensec Blog](https://blog.doyensec.com/2024/07/11/database-race-conditions.html) | 2024 |
| 7 | Qualys Threat Research Unit | regreSSHion: Remote Unauthenticated Code Execution Vulnerability in OpenSSH Server | [Qualys Blog](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server) | 2024 |
| 8 | Rachid A. (zhero_web_security) | Eclipse on Next.js: Conditioned Exploitation of an Intended Race-Condition | [zhero_web_sec Research](https://zhero-web-sec.github.io/research-and-things/eclipse-on-nextjs-conditioned-exploitation-of-an-intended-race-condition) | 2024 |
| 9 | Rachid A. (zhero_web_security) | Next.js and Cache Poisoning: A Quest for the Black Hole (CVE-2024-46982) | [zhero_web_sec Research](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole) | 2024 |
| 10 | Pepe Vila et al. | On Race Vulnerabilities in Web Applications | [SpringerLink](https://link.springer.com/chapter/10.1007/978-3-540-70542-0_7) | 2008 |
| 11 | — | Navigating the Concurrency Landscape: A Survey of Race Condition Vulnerability Detectors | [arXiv](https://arxiv.org/abs/2312.14479) | 2023 |
| 12 | — | Semantic Web Racer: Dynamic Security Testing of the Web Application Against Race Condition in the Business Layer | [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0957417422000677) | 2022 |
| 13 | Yoochan Lee et al. | EXPRACE: Exploiting Kernel Races through Raising Interrupts (USENIX Security 2021) | [USENIX](https://www.usenix.org/system/files/sec21fall-lee-yoochan.pdf) | 2021 |

### CVE Advisories

| # | CVE ID | Description | URL | Year |
|---|---|---|---|---|
| 1 | CVE-2024-6387 | OpenSSH regreSSHion — Signal handler race condition in sshd (CVSS 8.1) | [NVD](https://nvd.nist.gov/vuln/detail/cve-2024-6387) | 2024 |
| 2 | CVE-2024-50379 | Apache Tomcat TOCTOU Race in JSP Compilation — RCE on case-insensitive FS (CVSS 9.8) | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2024-50379) | 2024 |
| 3 | CVE-2024-56337 | Apache Tomcat TOCTOU Race — Incomplete fix for CVE-2024-50379 | [CVE Details](https://www.cvedetails.com/cve/CVE-2024-56337/) | 2024 |
| 4 | CVE-2024-46982 | Next.js Cache Poisoning via Race Condition in Pages Router | [GitHub Advisory](https://github.com/advisories/GHSA-gp8f-8m3g-qvj9) | 2024 |
| 5 | CVE-2025-32421 | Next.js "Eclipse" bypass of CVE-2024-46982 patch | [GitHub Advisory](https://github.com/advisories/GHSA-qpjv-v59x-3qc4) | 2025 |
| 6 | CVE-2024-58248 | nopCommerce — Duplicate gift card redemption via missing order placement locking | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-58248) | 2024 |
| 7 | CVE-2024-21626 | runC — Container escape via file descriptor leak + symlink race | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-21626) | 2024 |
| 8 | CVE-2006-5051 | OpenSSH Signal Handler Race Condition (original, regressed by CVE-2024-6387) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2006-5051) | 2006 |

### Bug Bounty Reports

| # | Program | Title | URL |
|---|---|---|---|
| 1 | HackerOne | Race Condition in Flag Submission | [Report #454949](https://hackerone.com/reports/454949) |
| 2 | HackerOne | Race Condition Leads to Duplicate Payouts | [Report #604534](https://hackerone.com/reports/604534) |
| 3 | Internet Bug Bounty | Race Conditions in OAuth 2.0 API Implementations | [Report #55140](https://hackerone.com/reports/55140) |
| 4 | HackerOne | Race Conditions in Popular Functionalities | [Report #146845](https://hackerone.com/reports/146845) |
| 5 | Instacart | Race Condition — Multiple Coupon Redemptions | [Report #157996](https://hackerone.com/reports/157996) |
| 6 | Stripe | Promotion Code Race Condition | [Report #1717650](https://hackerone.com/reports/1717650) |
| 7 | Reverb.com | Gift Card Redemption Race | [Report #759247](https://hackerone.com/reports/759247) |
| 8 | Shopify | Race Condition in Adding Team Members (staff limit bypass) | [Report #176127](https://hackerone.com/reports/176127) |
| 9 | Shopify | Race Condition at Create New Location (location limit bypass) | [Report #413759](https://hackerone.com/reports/413759) |
| 10 | — | Top HackerOne Race Condition Reports (curated list) | [GitHub — reddelexc](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPRACECONDITION.md) |

### Tools & Repositories

| # | Tool | Author / Organization | Description | URL |
|---|---|---|---|---|
| 1 | Turbo Intruder | PortSwigger (James Kettle) | Burp Suite extension; single-packet attack race scripts | [GitHub](https://github.com/PortSwigger/turbo-intruder) |
| 2 | h2spacex | nxenon | HTTP/2 Single Packet Attack library (Scapy-based) | [GitHub](https://github.com/nxenon/h2spacex) |
| 3 | RacePwn | racepwn | Race condition framework (librace C + racepwn Go) | [GitHub](https://github.com/racepwn/racepwn) |
| 4 | Race The Web | TheHackerDev | Race condition tester with RESTful API for CI integration | [GitHub](https://github.com/TheHackerDev/race-the-web) |
| 5 | race-condition-exploit | andresriancho | Web application race condition exploitation tool | [GitHub](https://github.com/andresriancho/race-condition-exploit) |
| 6 | db-race-conditions-playground | Doyensec | Playground for database isolation-level race testing | [GitHub](https://github.com/doyensec/db-race-conditions-playground) |
| 7 | WannaRace | Xib3rR4dAr | Intentionally vulnerable app for race condition practice | [GitHub](https://github.com/Xib3rR4dAr/WannaRace) |

### Blog Posts & Writeups

| # | Author / Organization | Title | URL |
|---|---|---|---|
| 1 | PortSwigger | Race Conditions — Web Security Academy (educational labs) | [Web Security Academy](https://portswigger.net/web-security/race-conditions) |
| 2 | Doyensec | Common OAuth Vulnerabilities (includes token exchange race) | [Doyensec Blog](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html) |
| 3 | OffSec | RegreSSHion Exploit, CVE-2024-6387: A Write-Up | [OffSec Blog](https://www.offsec.com/blog/regresshion-exploit-cve-2024-6387/) |
| 4 | Mend.io | CVE-2024-50379: A Critical Race Condition in Apache Tomcat | [Mend Blog](https://www.mend.io/blog/cve-2024-50379-a-critical-race-condition-in-apache-tomcat/) |
| 5 | Unit 42 (Palo Alto Networks) | Threat Brief: CVE-2024-6387 OpenSSH RegreSSHion Vulnerability | [Unit 42](https://unit42.paloaltonetworks.com/threat-brief-cve-2024-6387-openssh/) |
| 6 | Bugcrowd | Racing Against Time: An Introduction to Race Conditions | [Bugcrowd Blog](https://www.bugcrowd.com/blog/racing-against-time-an-introduction-to-race-conditions/) |
| 7 | YesWeHack | Ultimate Bug Bounty Guide to Race Condition Vulnerabilities | [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities) |
| 8 | HackTricks | Race Condition (community cheat sheet) | [HackTricks](https://book.hacktricks.xyz/pentesting-web/race-condition) |
| 9 | SwissKyRepo | PayloadsAllTheThings — Race Condition | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition) |
| 10 | Cristian Cornea | Top 25 Race Condition Bug Bounty Reports | [Medium](https://corneacristian.medium.com/top-25-race-condition-bug-bounty-reports-84f9073bf9e5) |

### Standards & Documentation

| # | Organization | Title | URL |
|---|---|---|---|
| 1 | MITRE | CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) |
| 2 | MITRE | CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition | [CWE-367](https://cwe.mitre.org/data/definitions/367.html) |
| 3 | IETF | RFC 6749 — The OAuth 2.0 Authorization Framework (§4.1.2: authorization codes MUST be single-use) | [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) |
| 4 | IETF | RFC 6819 — OAuth 2.0 Threat Model and Security Considerations | [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) |
| 5 | OWASP | Testing for OAuth Weaknesses (Web Security Testing Guide) | [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses) |
| 6 | PostgreSQL | Transaction Isolation Documentation | [PostgreSQL Docs](https://www.postgresql.org/docs/current/transaction-iso.html) |
| 7 | MySQL | InnoDB Transaction Isolation Levels | [MySQL Docs](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-isolation-levels.html) |
