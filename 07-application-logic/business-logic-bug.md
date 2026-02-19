# Business Logic Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

Business logic vulnerabilities arise not from implementation-level coding errors (like SQL injection or XSS) but from **design flaws in how applications model, enforce, and transition through business rules**. They exploit the gap between what a system *technically allows* and what it *intends to permit*. Because these flaws operate within the application's legitimate processing flow, they are invisible to traditional scanners (SAST, DAST, WAF) and require semantic understanding of the business domain to detect.

This taxonomy organizes the entire attack surface of business logic vulnerabilities across three axes:

- **Axis 1 — Mutation Target (Primary)**: The structural component of the application's business logic being manipulated. This axis forms the main body of the document, with 10 top-level categories covering every class of business logic abuse.
- **Axis 2 — Exploitation Mechanism (Cross-Cutting)**: The fundamental *how* — the type of assumption violation or trust boundary breach that makes the mutation work. These mechanisms recur across multiple target categories.
- **Axis 3 — Impact Domain (Mapping)**: The real-world consequence domain — where the damage materializes (financial, access, data, operational).

### Axis 2: Cross-Cutting Exploitation Mechanisms

These mechanisms apply across all §1–§10 categories and explain *why* each mutation succeeds:

| Mechanism Code | Name | Description |
|---|---|---|
| **M1** | Assumption Violation | Exploiting implicit developer assumptions about user behavior (e.g., users will follow the UI flow) |
| **M2** | Sequential Bypass | Skipping, reordering, or repeating required steps in a multi-step workflow |
| **M3** | Parameter Manipulation | Altering values the server implicitly trusts from the client (prices, IDs, quantities, roles) |
| **M4** | Temporal Exploitation | Exploiting timing windows between check and use (TOCTOU), or between validation and enforcement |
| **M5** | State Confusion | Forcing the application into an invalid or unintended state via unexpected transitions |
| **M6** | Trust Boundary Violation | Exploiting misplaced trust between client/server, inter-service, or inter-component boundaries |
| **M7** | Semantic Gap Exploitation | Leveraging differences between how two components interpret the same data or rule |

### Foundational Principle: The Turing Machine Model

The OWASP Business Logic Abuse Top 10 (2025) models business-logic vulnerabilities using Turing machine primitives, providing a universal framework: any business rule can be expressed as a Turing machine (tape = data/memory, head = data access, states = workflow positions, transitions = logic rules). This guarantees that the taxonomy below can represent every possible logic flaw. Each category in this taxonomy maps to one or more of these primitives being abused.

---

## §1. Data Integrity and Input Validation Abuse (Tape Manipulation)

When applications fail to enforce server-side validation of business-critical parameters — prices, quantities, currencies, user-supplied identifiers — attackers can directly manipulate the data that drives business decisions. This is the most fundamental class of business logic vulnerability: the application *trusts data it should verify*.

### §1-1. Price and Amount Manipulation

The server accepts client-supplied pricing data without independent verification against its own records.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Direct Price Override** | Intercept checkout request, modify price/amount field to arbitrary value (e.g., `price=0.01`) | Server uses client-supplied price instead of looking up from product catalog | M3, M6 |
| **Currency Parameter Swap** | Change currency code (e.g., `currency=VND` instead of `USD`) while keeping numeric amount, exploiting exchange rate differential | Server accepts currency parameter without recalculating amount | M3 |
| **Tax/Fee Removal** | Remove or zero-out tax, shipping, or service fee parameters from the request | Server calculates total from client-supplied line items rather than recalculating | M3, M6 |
| **Discount Amount Injection** | Add or modify a discount parameter (e.g., `discount=99.99`) not exposed in the UI | Server applies discount values from request without authorization check | M3, M1 |

**Example**: Intercepting `POST /checkout` and modifying `{"product_id": 42, "price": 1299.99}` to `{"product_id": 42, "price": 0.01}`. If the server uses the client-supplied price, the attacker purchases at a penny.

### §1-2. Quantity and Boundary Exploitation

Numeric input boundaries are not enforced, allowing values outside the expected range.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Negative Quantity Injection** | Set quantity to negative value (e.g., `qty=-5`), causing the system to *credit* instead of charge | Server performs arithmetic on unsigned input without range validation | M3 |
| **Integer Overflow/Wraparound** | Submit extremely large quantity (e.g., `qty=2147483647`) causing signed integer overflow to negative | Server uses fixed-width integer arithmetic without overflow checks; 32-bit signed int wraps at 2^31 | M3 |
| **Zero-Value Bypass** | Set quantity or amount to zero to trigger edge-case behavior (free order, null transaction) | Server doesn't reject zero-value orders or treats them as valid | M3, M1 |
| **Fractional Quantity Abuse** | Submit fractional quantities (e.g., `qty=0.001`) for items that should only be whole numbers | Server accepts float where integer is expected, rounding errors create pricing discrepancies | M3, M7 |
| **Maximum Bound Overflow** | Exceed defined maximum limits (e.g., transfer amount > account balance) where only client-side validation enforces the cap | Business rules checked only in frontend JavaScript | M6 |

**Example**: On an e-commerce platform, adding `qty=2147483647` of a $10 item causes the total to overflow a 32-bit signed integer, wrapping to a negative value. The attacker "pays" a negative total, effectively receiving a credit.

### §1-3. Identifier and Reference Manipulation

Object references (IDs, keys, tokens) are predictable or unvalidated, allowing cross-object operations.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **IDOR (Insecure Direct Object Reference)** | Replace object ID in request (e.g., `user_id=1001` → `user_id=1002`) to access another user's data | Server uses client-supplied ID without ownership verification | M3, M6 |
| **Cross-Entity Reference Swap** | Swap reference IDs between different entity types or contexts (e.g., use order_id from account A in account B's refund request) | Server validates existence but not ownership/context | M3, M5 |
| **Enumerable ID Brute-Force** | Iterate sequential/predictable IDs to discover and access objects | Object IDs are sequential integers without authorization checks | M3, M1 |

### §1-4. Mass Assignment and Property Injection

API endpoints bind request payloads directly to server-side objects without filtering which fields the client may set.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Role/Privilege Injection** | Add `{"role": "admin"}` or `{"is_admin": true}` to a profile update request | Server auto-binds all JSON fields to the user object without allowlist | M3, M6 |
| **Internal State Override** | Set fields like `{"verified": true}`, `{"balance": 99999}`, `{"status": "approved"}` | ORM/framework auto-maps request fields to database columns | M3, M5 |
| **Hidden Field Discovery** | Use API documentation, error messages, or schema introspection to discover internal fields not exposed in the UI | GraphQL introspection enabled, verbose error messages leak field names | M3, M1 |

---

## §2. State Machine and Workflow Violations (Transition Abuse)

Applications implement multi-step processes (checkout, registration, approval) as implicit state machines. When transition validation is incomplete — steps can be skipped, repeated, or reordered — attackers bypass mandatory business logic.

### §2-1. Sequential Step Bypass

Mandatory steps in a multi-step workflow can be skipped by directly requesting a later step.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Direct-to-Final-Step** | Skip intermediate steps (e.g., go from cart directly to order confirmation, bypassing payment) | Each step is a separate endpoint; server doesn't verify all prior steps completed | M2, M1 |
| **Payment Step Skip** | In a checkout flow (cart → address → payment → confirm), directly POST to the confirmation endpoint | Server checks session existence but not whether payment was processed | M2 |
| **Verification Bypass** | Skip email/phone verification step by directly accessing the post-verification endpoint | Verification flag is set client-side or not checked on subsequent endpoints | M2, M6 |
| **Approval Chain Bypass** | In multi-level approval workflows, submit directly to the final approval endpoint | Intermediate approval states are not tracked server-side | M2, M5 |

**Example**: A multi-step registration requires: (1) enter details → (2) verify email → (3) set password → (4) activate account. An attacker directly POSTs to step 4's endpoint with required parameters, bypassing email verification entirely.

### §2-2. State Transition Manipulation

Force invalid transitions between application states that the business logic doesn't anticipate.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Backwards State Transition** | Transition an order from "shipped" back to "pending" to modify contents or cancel | State machine allows reverse transitions without authorization | M5 |
| **Orphaned State Exploitation** | Access functionality available only in a transitional state by keeping the session in that state indefinitely | No timeout or expiration on intermediate states | M5, M4 |
| **Parallel State Exploitation** | Start multiple instances of the same workflow simultaneously to create conflicting states | No mutex or session-level workflow locking | M4, M5 |
| **Terminal State Re-Entry** | Reopen a completed/closed transaction (e.g., reopen a settled insurance claim, re-activate a cancelled subscription) | Terminal states don't have re-entry guards | M5 |

### §2-3. Process Repetition and Replay

Actions intended to be one-time can be repeated for additional benefit.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Action Replay** | Replay a valid request (coupon redemption, bonus claim, referral reward) multiple times | No idempotency key or one-time-use enforcement | M2, M4 |
| **Coupon/Promo Code Stacking** | Apply multiple discount codes when only one should be allowed, or apply the same code multiple times | Server doesn't track applied codes per session/order | M2, M1 |
| **Gift Card Loop** | Purchase gift cards with gift card balance, cycling through promotions at each step to generate infinite money | Promotional discounts apply to gift card purchases that can then be used for more gift cards | M2, M7 |
| **Referral Self-Loop** | Create multiple accounts to refer yourself, collecting referral bonuses | Referral system checks only referral code validity, not identity linkage | M2, M1 |

**Example (Infinite Money)**: (1) Apply a promotion code for 30% off → (2) Buy a $100 gift card for $70 → (3) Redeem gift card for $100 balance → (4) Repeat. Each cycle generates $30 in profit, infinitely.

### §2-4. Lifecycle and Orphaned Resource Abuse

Application objects (tokens, sessions, temporary resources) persist beyond their intended lifecycle.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Orphaned Token Reuse** | Use expired or revoked tokens that the server still honors | Token revocation is eventual (not immediate) or only checked at issuance | M4, M5 |
| **Dangling Reference Exploitation** | Access resources through references that should have been invalidated (deleted user's active sessions, removed product's active orders) | Cascading invalidation not implemented | M5 |
| **Temporary Resource Persistence** | Exploit trial accounts, temporary URLs, or staging environments that aren't properly cleaned up | No automated lifecycle management for temporary resources | M5, M1 |

---

## §3. Access Control and Authorization Bypass (Permission Boundary Abuse)

When implementations omit, misapply, or inconsistently enforce role and permission checks, attackers manipulate role identifiers, escalate privileges, or access unauthorized operations.

### §3-1. Vertical Privilege Escalation

Gain access to higher-privilege functionality (user → admin).

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Direct Admin Endpoint Access** | Access administrative endpoints (e.g., `/admin/users/delete`) without role verification | Admin functionality exists at predictable URLs with no server-side role check | M2, M6 |
| **Role Parameter Injection** | Modify role indicator in request (cookie, header, hidden field, JWT claim) to escalate privileges | Role is determined from client-supplied data without server-side verification | M3 |
| **Function-Level Authorization Gap** | Certain admin functions (bulk export, configuration changes) lack authorization checks while main admin panel is protected | Inconsistent authorization enforcement across endpoints | M1, M6 |
| **Forced Browsing to Privileged Resources** | Directly access admin-only files, API docs, debug endpoints, or configuration panels | Authorization enforced at UI layer but not at resource layer | M2, M6 |

### §3-2. Horizontal Privilege Escalation

Access data or functionality belonging to another user at the same privilege level.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **BOLA (Broken Object Level Authorization)** | Modify object identifier in API calls to access another user's resources | API enforces authentication but not object-level ownership checks | M3, M6 |
| **Cross-Tenant Data Access** | In multi-tenant SaaS, access another tenant's data by manipulating tenant identifier | Tenant isolation relies on application logic rather than database-level separation | M3 |
| **Shared Resource Scope Escape** | Access another user's private resources through shared resource endpoints (e.g., shared folder listing exposes private files) | Shared and private resources coexist without proper scoping | M7 |

### §3-3. Context-Dependent Authorization Bypass

Authorization that is correct in one context but exploitable in another.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **HTTP Method Switching** | An endpoint blocks `DELETE` but allows `POST` with `_method=DELETE` or uses a different method (GET vs POST) | Authorization rules are method-specific but the application supports method override | M7, M1 |
| **API Version Bypass** | Access deprecated API version (`/api/v1/admin`) that lacks authorization checks present in current version (`/api/v3/admin`) | Old API versions remain deployed without backported security controls | M1, M2 |
| **Content-Type Authorization Gap** | Same endpoint enforces different authorization based on content type (JSON vs XML vs form-data) | Authorization middleware is content-type-specific | M7 |
| **GraphQL/Batch Authorization Bypass** | Batch multiple queries in a single GraphQL request to bypass per-query authorization limits | Authorization checked at the request level, not per-operation within a batch | M7, M1 |

---

## §4. Concurrency and Timing Exploitation (Temporal Window Abuse)

Race conditions in business logic create temporal windows between check and use, allowing operations that should be mutually exclusive to execute in parallel.

### §4-1. Time-of-Check to Time-of-Use (TOCTOU)

The system validates a condition (balance, availability, coupon status) and then acts on it, but the condition changes between check and use.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Balance Double-Spend** | Send two simultaneous withdrawal/purchase requests; both pass the balance check before either deducts | Balance check and deduction are not atomic; no row-level locking | M4 |
| **Coupon Race Condition** | Send parallel requests to redeem a single-use coupon; both validate it as unused before either marks it as used | Coupon status check and update are non-atomic operations | M4 |
| **Inventory Oversell** | Simultaneous purchases of the last remaining item; both pass stock check before either decrements | Stock check and decrement are separate, non-locked operations | M4 |
| **Rate Limit Race** | Burst requests within the same timing window before the rate limiter updates its counter | Rate limiter uses eventually-consistent counters or has a check-update gap | M4 |

**Example**: Using Turbo Intruder or single-packet attack technique, an attacker sends 30 parallel requests to redeem a $200 discount coupon. All 30 pass the "unused" check simultaneously, each applying the discount, resulting in $6,000 worth of unauthorized discounts.

### §4-2. Concurrent Workflow Manipulation

Exploit parallel processing paths to achieve states that sequential processing would prevent.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Parallel Checkout Exploitation** | Start multiple checkout sessions for the same cart simultaneously; both succeed, duplicating the order at the cost of one payment | Session-level cart locking not implemented | M4, M5 |
| **Concurrent Approval** | Submit the same request through multiple approval channels simultaneously | Approval system doesn't lock the request during processing | M4 |
| **File Upload Race** | Upload a file and access it before server-side validation/processing completes (e.g., access malicious upload before antivirus scan) | Async processing pipeline with accessible intermediate storage | M4, M2 |

### §4-3. Timing Side-Channel in Business Logic

Response timing differences leak information about business logic state.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Existence Oracle via Timing** | Different response times for valid vs. invalid usernames, coupons, or internal IDs | Server performs additional lookups for valid entities, creating measurable timing differences | M4, M7 |
| **Feature Gate Timing Leak** | Premium features check timing reveals feature availability even when access is denied | Feature availability check occurs before authorization denial | M4, M7 |

---

## §5. Resource and Quota Management Violations (Boundary Exhaustion)

Applications expose endpoints that consume computational, financial, or operational resources. When systems fail to enforce proper limits, attackers exhaust resources, exceed quotas, or abuse usage-based billing.

### §5-1. Rate Limit and Throttle Bypass

Circumvent intended limits on the frequency or volume of operations.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Distributed Source Rotation** | Rotate source IPs, API keys, or user agents to reset per-source rate limits | Rate limiting is per-IP or per-key without account-level aggregation | M1, M3 |
| **Endpoint Variant Bypass** | Access the same functionality through different URL paths, API versions, or parameter encodings to bypass endpoint-specific rate limits | Rate limits applied per-URL-pattern, not per-business-function | M7 |
| **Header Manipulation Bypass** | Add `X-Forwarded-For`, `X-Real-IP`, or other proxy headers to reset IP-based rate limits | Server trusts client-supplied proxy headers for rate limiting decisions | M3, M6 |
| **Session Reset Bypass** | Create new sessions or re-authenticate to reset session-based rate limits (e.g., login attempt limits) | Rate limit state bound to session rather than account or IP | M5 |

### §5-2. Resource Quota Exploitation

Exceed intended usage limits for free tiers, trial accounts, or metered services.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Trial Abuse / Account Cycling** | Create new accounts to repeatedly access free tier or trial benefits | No identity linkage between accounts (email alias, phone number, device fingerprint) | M1, M2 |
| **Quota Boundary Manipulation** | Modify quota-related parameters (e.g., API call count, storage usage) in requests | Quota tracking uses client-reported metrics | M3, M6 |
| **Feature Limit Bypass** | Access premium features beyond free-tier limits by manipulating feature-gate parameters | Feature gating checked client-side or through manipulable API parameters | M3, M6 |
| **Metered Service Abuse** | Exploit rounding, minimum billing thresholds, or free-tier windows to consume services without paying | Billing system has exploitable rounding or threshold behaviors | M7, M1 |

### §5-3. Denial-of-Service via Business Logic

Abuse legitimate business operations to cause resource exhaustion.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Cart/Reservation Bombing** | Reserve all inventory (hotel rooms, flight seats, concert tickets) without purchasing, preventing legitimate sales | Reservation system has no timeout, deposit requirement, or limit per user | M1, M5 |
| **Notification/Email Bombing** | Trigger mass notifications, password resets, or verification emails by abusing legitimate features | No rate limit on notification-triggering endpoints | M1 |
| **Expensive Query Abuse** | Trigger computationally expensive operations (large reports, complex searches, bulk exports) to degrade service | No resource consumption limits on data-intensive endpoints | M1 |
| **Storage Exhaustion** | Upload maximum-size files repeatedly to exhaust storage quotas for the entire platform | Per-file limits exist but aggregate limits are not enforced | M1 |

---

## §6. Authentication and Session Logic Abuse (Identity Boundary Violation)

Flaws in the authentication and session management *logic* — distinct from cryptographic weaknesses — that allow attackers to bypass identity verification, hijack sessions, or impersonate users.

### §6-1. Authentication Flow Bypass

Circumvent authentication by exploiting logical flaws in the authentication workflow rather than breaking cryptographic protections.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **MFA Step Skip** | Complete primary authentication, then directly access the post-MFA endpoint without submitting the second factor | MFA verification is a separate step that the server doesn't enforce as mandatory before granting access | M2 |
| **Authentication State Machine Flaw** | Manipulate the authentication state to jump from "credentials entered" to "fully authenticated" without intermediate validation | Authentication uses client-side state tracking (cookies, hidden fields) to determine current step | M5, M6 |
| **Password Reset Logic Abuse** | Use the password reset flow to bypass authentication entirely (e.g., reset token grants session without completing reset) | Password reset endpoint creates authenticated session before password is actually changed | M2, M5 |
| **OAuth/SSO Flow Manipulation** | Modify OAuth callback parameters (`state`, `redirect_uri`, `code`) to obtain tokens for other users or bypass consent | Insufficient validation of OAuth state parameter or redirect URI matching | M3, M5 |
| **"Remember Me" Token Abuse** | Steal or predict persistent authentication tokens that bypass full login flow | Remember-me tokens are predictable, long-lived, or not bound to additional factors | M4, M6 |

### §6-2. Session Management Logic Flaws

Exploit logical weaknesses in how sessions are created, maintained, and terminated.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Session Fixation** | Set a known session ID before the victim authenticates; after they log in, the attacker's known session ID becomes authenticated | Server doesn't regenerate session ID upon authentication | M5 |
| **Token/Cookie Replay** | Capture and replay valid session tokens, JWTs, or cookies, particularly after logout | Logout doesn't invalidate server-side session state; JWT has no revocation mechanism | M4 |
| **Session Persistence After Permission Change** | User's session retains old permissions after role downgrade or account deactivation | Session permissions cached and not refreshed on each request | M4, M5 |
| **Cross-Session State Leakage** | User A's data bleeds into User B's session due to shared state in server-side caching or connection pooling | Application-level caching not properly scoped to sessions | M7 |

### §6-3. SSO and Federation Logic Abuse

Exploit logical flaws in single sign-on and federated identity systems.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **SAML Assertion Replay** | Replay a captured SAML assertion after its intended use or expiration | Service Provider doesn't check `NotOnOrAfter` timestamps or track assertion IDs for one-time use | M4 |
| **JWT Claim Manipulation** | Modify JWT claims (`sub`, `role`, `tenant_id`) in contexts where signature verification is flawed or absent | `alg: none` accepted, symmetric/asymmetric key confusion, or server only validates format not signature | M3, M6 |
| **IdP Confusion** | In multi-IdP environments, authenticate with one IdP but present the token to a service expecting a different IdP | Service doesn't validate token issuer against expected IdP for the requested resource | M7 |
| **Account Linking Exploitation** | Link an attacker-controlled SSO identity to a victim's existing account during account merge/linking flows | Account linking uses email or identifier matching without requiring proof of ownership of the existing account | M5, M1 |

---

## §7. Information Disclosure and Data Oracle Abuse (Internal State Leakage)

Applications inadvertently reveal internal state, business rules, or sensitive data through their business logic responses, enabling attackers to derive information they shouldn't possess.

### §7-1. Behavioral Oracles

Application behavior differences reveal information about internal state.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Error Message Information Leakage** | Different error messages for "user not found" vs. "wrong password" reveal valid usernames | Application provides context-specific error messages for different failure conditions | M7 |
| **Business Rule Exposure** | Application responses reveal validation rules, thresholds, or constraints (e.g., "Maximum transfer is $10,000", "Discount only applies to orders over $50") | Error messages or UI hints expose business rule boundaries | M7, M1 |
| **Feature Gate Detection** | Probing for premium features reveals which features exist and their access requirements | Feature availability can be determined through response code/content differences | M7 |
| **Pricing/Algorithm Reverse Engineering** | Systematic probing of inputs reveals pricing algorithms, scoring formulas, or decision criteria | Application deterministically responds to varying inputs, enabling function reconstruction | M7 |

### §7-2. Data Exposure Through Business Operations

Normal business operations expose more data than intended.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Verbose API Response** | API returns full object data (including internal fields) when only a subset should be visible | API serializes entire database model without field-level filtering | M1, M6 |
| **Search/Filter Data Leakage** | Search functionality reveals existence or attributes of objects the user shouldn't see (e.g., searching for internal user emails returns autocomplete suggestions) | Search indexes include data from all access levels | M7 |
| **Export/Report Over-Exposure** | Bulk export or report generation includes data beyond the user's authorization scope | Export queries don't apply the same access control filters as the UI | M6 |
| **Error-Triggered Data Disclosure** | Server errors (stack traces, debug output, database errors) reveal internal architecture, table names, or data | Debug/verbose error handling enabled in production | M1 |
| **Metadata Leakage** | Document metadata, EXIF data, HTTP headers, or API schemas expose internal infrastructure details | Metadata stripping not implemented before serving files or responses | M1 |

### §7-3. Indirect Data Oracle via Side Channels

Non-obvious channels reveal business-sensitive information.

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Location/Status Oracle** | Call metadata, delivery tracking, or service status endpoints reveal user location or activity | Data accessible without requiring authorization of the subject user (e.g., O2 UK location data via call metadata) | M6, M7 |
| **Existence Oracle** | Probing for resources (usernames, emails, account numbers) reveals whether they exist based on response differences | System gives different responses for "exists but unauthorized" vs. "doesn't exist" | M7 |
| **Enumeration via Business Workflow** | Use legitimate features (password reset, invitation, sharing) to enumerate valid accounts | "Password reset email sent" vs. "Account not found" responses differ | M7 |

---

## §8. Numeric and Type Boundary Abuse (Data Representation Exploitation)

Exploiting how the application handles data types, numeric boundaries, and type coercion to achieve unintended business logic outcomes.

### §8-1. Numeric Boundary Exploitation

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Signed Integer Wraparound** | Cause calculations to exceed `MAX_INT` (2,147,483,647 for 32-bit) so the result wraps to a negative number | Server uses signed integer arithmetic without overflow protection | M3 |
| **Floating-Point Precision Abuse** | Exploit IEEE 754 floating-point precision loss in financial calculations (e.g., `0.1 + 0.2 ≠ 0.3`) to create rounding discrepancies | Financial calculations use float/double instead of decimal/fixed-point types | M7 |
| **Rounding Error Accumulation** | Perform many small transactions where each rounds in the attacker's favor (salami attack) | Per-transaction rounding is economically insignificant but aggregation is not monitored | M7 |
| **Underflow to Zero** | Cause a value to round down to zero (e.g., a fee of $0.001 rounds to $0.00) to eliminate costs | Rounding applied before comparison against minimum thresholds | M7 |

### §8-2. Type Confusion and Coercion

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **String-to-Number Coercion** | Submit `"0"` (string) where `0` (integer) is expected, or vice versa, exploiting type coercion differences in comparisons | Loosely-typed language (JavaScript, PHP) performs implicit type coercion in comparisons | M7 |
| **Boolean Coercion Bypass** | Submit `""`, `0`, `null`, `[]`, or `"false"` to bypass truthy checks in validation logic | Application relies on truthiness evaluation rather than explicit boolean comparison | M7, M3 |
| **Array/Object Where Scalar Expected** | Send `{"price": [0]}` or `{"admin": {"$gt": ""}}` where a scalar value is expected | Server doesn't validate input types; ORM/query builder processes complex types as operators (NoSQL injection boundary) | M7, M3 |
| **Data Type Smuggling** | API accepts values in formats that bypass type checks (e.g., scientific notation `1e-10` for a price, Unicode digits `٣` for the number 3) | Input parsing handles special formats but validation logic doesn't | M7 |

### §8-3. Encoding and Representation Abuse

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Character Encoding Differential** | Different system components interpret the same bytes differently (UTF-8 vs. Latin-1, NFC vs. NFD normalization) | Multi-component system without unified encoding handling | M7 |
| **Locale-Dependent Parsing** | Exploit locale differences in number parsing (`,` vs `.` as decimal separator) to submit different values than intended | Server parses numbers using a different locale than the client | M7 |
| **Case Sensitivity Mismatch** | `Admin@example.com` and `admin@example.com` treated as different accounts by one system but the same by another | Inconsistent case normalization across components (registration vs. login) | M7 |

---

## §9. API and Interface Abuse (Contract Violation)

Exploiting assumptions about how APIs and interfaces will be consumed, including hidden endpoints, undocumented features, and interface contract violations.

### §9-1. Hidden and Shadow Functionality

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Shadow Endpoint Discovery** | Access undocumented API endpoints (debug, admin, internal) through path guessing, documentation leaks, or client-side code analysis | Internal/debug endpoints deployed to production without authentication | M1, M2 |
| **GraphQL Introspection Abuse** | Use GraphQL introspection queries to discover the full schema, including internal types, mutations, and hidden fields | Introspection enabled in production, revealing the complete API surface | M1 |
| **API Documentation Exposure** | Access Swagger/OpenAPI specs, Postman collections, or developer documentation that reveal internal endpoints | API documentation served from predictable paths without access control | M1 |
| **Debug/Test Mode Activation** | Activate debug or test modes through hidden parameters (`?debug=true`, `X-Debug: 1`) that bypass business logic | Debug flags not stripped in production deployment | M3, M1 |

### §9-2. Interface Contract Violations

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Method Override Exploitation** | Use `X-HTTP-Method-Override`, `_method` parameter, or content-type manipulation to invoke different handlers | Application supports method override but authorization is method-specific | M7 |
| **Content-Type Confusion** | Send request body in unexpected format (XML instead of JSON, form-data instead of JSON) to bypass validation or trigger different parsing paths | Server accepts multiple content types but validation differs per type | M7 |
| **Batch/Bulk Operation Abuse** | Combine authorized and unauthorized operations in a single batch request | Batch processor checks authorization at the batch level, not per-operation | M7, M6 |
| **WebSocket Business Logic Bypass** | Perform business operations via WebSocket connections that lack the same authorization and validation as REST endpoints | WebSocket handlers implemented separately from REST with incomplete security controls | M6, M1 |

### §9-3. Client-Side Logic Exploitation

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Client-Side Validation Bypass** | Skip all client-side validation (JavaScript, mobile app) by sending requests directly to the API | Server relies on client-side validation without server-side verification | M6 |
| **Embedded Business Logic Reverse Engineering** | Decompile mobile apps, JavaScript bundles, or Flash/Silverlight to extract business logic, API keys, and hidden endpoints | Business-critical logic or secrets embedded in client-side code | M1 |
| **Feature Flag Client-Side Override** | Modify client-side feature flags (localStorage, cookies, JavaScript variables) to enable premium or hidden features | Feature availability determined by client-side flags without server-side enforcement | M6, M3 |

---

## §10. Domain-Specific Business Logic Abuse (Vertical Attack Surfaces)

Business logic vulnerabilities that are specific to particular industry verticals and business domains, exploiting the unique rules and workflows of each domain.

### §10-1. E-Commerce and Payment Logic

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Cart Manipulation After Discount** | Apply discount for qualifying cart, then remove items before checkout while keeping discount | Discount eligibility checked at application time but not re-validated at checkout | M2, M5 |
| **Return/Refund Abuse** | Initiate refund for an order, receive refund, but also keep the product (or refund processed without return verification) | Refund process doesn't verify product return status or allows duplicate refunds | M2, M5 |
| **Payment Callback Manipulation** | Forge or replay payment gateway callback (IPN/webhook) to mark unpaid orders as paid | Application trusts payment callback without verifying directly with the payment processor | M3, M6 |
| **Partial Payment Exploitation** | Pay a lower amount or partial amount that the system accepts due to rounding or partial payment feature abuse | Payment verification checks for "payment exists" rather than "payment amount matches order total" | M3, M7 |
| **Gift Card / Store Credit Laundering** | Convert stolen payment methods to gift cards/store credit, then use legitimate-looking store credit for purchases | Gift card purchase treated as a normal product without enhanced fraud checks | M1, M2 |

### §10-2. Financial and Fintech Logic

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Double-Spend in Digital Assets** | Exploit race conditions to spend the same digital balance twice (cryptocurrency, loyalty points, in-app currency) | Balance check and deduction not atomic; no distributed locking | M4 |
| **Cross-Currency Arbitrage** | Exploit stale exchange rates or rounding differences between currency conversion operations | Exchange rates cached or updated asynchronously; rounding applied at each step | M7, M4 |
| **Loan/Credit Stacking** | Simultaneously apply for multiple loans before any single approval updates the credit profile | Credit check is point-in-time and multiple applications can pass concurrently | M4 |
| **KYC Bypass via Account Linking** | Use a verified account to vouch for or link to unverified accounts, inheriting KYC status | Account linking/family features transfer trust without re-verification | M5, M1 |
| **Smart Contract Logic Exploitation** | Exploit re-entrancy, oracle manipulation, or logic bugs in DeFi protocols | Smart contract functions don't follow checks-effects-interactions pattern; price oracles are manipulable | M5, M4 |

### §10-3. Subscription and SaaS Logic

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Downgrade Retention** | Downgrade subscription tier while retaining premium features already provisioned (data, API access, storage) | Downgrade doesn't revoke already-provisioned resources | M5 |
| **Trial Extension / Reset** | Repeatedly create accounts or manipulate trial parameters to extend free trial indefinitely | No device fingerprinting, phone verification, or payment method deduplication for trial access | M1, M2 |
| **Plan Limit Circumvention** | Access beyond-plan features by manipulating API parameters, using deprecated endpoints, or exploiting grandfathered features | Plan limits enforced at the UI layer but not at the API layer | M6 |
| **Cancellation Window Exploitation** | Exploit the gap between cancellation request and actual deactivation to extract maximum value | Deactivation is eventual (end of billing period) but all features remain accessible | M4, M1 |

### §10-4. Booking and Reservation Logic

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Phantom Reservation** | Reserve high-demand inventory (flights, hotel rooms, concert tickets) without completing purchase to deny availability to others | Reservation holds have no timeout or monetary penalty | M5, M1 |
| **Overbooking Exploitation** | Exploit timing gaps in availability systems to create bookings beyond actual capacity | Distributed booking systems have eventual consistency in availability counts | M4 |
| **Loyalty Point Manipulation** | Transfer, pool, or manufacture loyalty points through program rule exploitation (status runs, mileage pooling edge cases) | Loyalty program rules create exploitable interactions when combined in unexpected ways | M7, M2 |

### §10-5. Voting, Contest, and Gamification Logic

| Subtype | Mechanism | Key Condition | Exploitation Mechanism |
|---|---|---|---|
| **Vote/Rating Manipulation** | Cast multiple votes using multiple accounts, session manipulation, or race conditions | Voter identity verification insufficient (cookie-based, IP-based) | M1, M4 |
| **Leaderboard/Score Manipulation** | Submit falsified scores or exploit game mechanics to achieve impossible rankings | Score validation is client-side; server accepts any submitted score | M6, M3 |
| **Reward/Achievement Farming** | Automate gameplay or social actions to accumulate rewards beyond intended rates | Anti-automation measures insufficient; business logic rewards raw volume | M1 |

---

## Attack Scenario Mapping (Axis 3: Impact Domain)

| Impact Domain | Architecture/Context | Primary Mutation Categories |
|---|---|---|
| **Financial Fraud** | E-commerce, fintech, payment processing | §1 + §4 + §10-1 + §10-2 |
| **Unauthorized Access** | Multi-tenant SaaS, enterprise applications | §3 + §6 + §9 |
| **Data Exfiltration** | API-driven applications, microservices | §7 + §3-2 + §9-1 |
| **Service Disruption** | High-availability platforms, booking systems | §5 + §4 + §10-4 |
| **Privilege Escalation** | Role-based access control systems | §3-1 + §1-4 + §6-1 |
| **Regulatory/Compliance Violation** | Financial services, healthcare, data privacy | §7 + §3 + §6-3 |
| **Inventory/Resource Manipulation** | E-commerce, ticketing, resource allocation | §5-3 + §10-4 + §4-1 |
| **Reputation Damage** | Social platforms, review/voting systems | §10-5 + §5-3 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 + §6-1 | CVE-2025-29927 (Next.js) — `x-middleware-subrequest` header bypass skipped authentication middleware entirely | Critical. Allowed complete auth bypass on all Next.js middleware-protected routes |
| §1-4 + §3-1 | Mass assignment in various platforms (HackerOne aggregate) | 45% of total bounty awards on HackerOne directed at business logic errors |
| §4-1 | Coupon race condition (HackerOne report) — Turbo Intruder used for 30 parallel coupon redemptions | $600,000 in unauthorized fee-free transactions |
| §10-2 | DeFi smart contract logic exploits (2024 aggregate) — re-entrancy, oracle manipulation, bridge logic flaws | $2.013B total losses across 410 incidents in 2024 |
| §7-3 | O2 UK location data exposure — call metadata revealed user location (Data Oracle + Missing Permissions) | Regulatory investigation; privacy violation |
| §6-3 | HashiCorp Vault / CyberArk Conjur logic flaws — authentication bypass, identity impersonation, policy enforcement circumvention (BlackHat 2024) | Secret exfiltration, identity impersonation, arbitrary code execution |
| §9-1 | Open GraphQL introspection + shadow signup endpoint bypassing email validation | Account creation without verification; unauthorized access |
| §2-3 | Unlimited discount redemption (HackerOne) — single coupon applied multiple times via replay | Significant financial impact on merchant |
| §10-2 | DMM Bitcoin hack (2024) — $308M cryptocurrency theft attributed to Bluenoroff group via logic and social engineering | $308M stolen; largest single crypto hack of 2024 |
| §1-2 + §8-1 | PortSwigger Low-Level Logic Flaw lab — integer overflow in shopping cart total | Cart total wraps negative, attacker receives credit |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Burp Suite + Extensions** (Manual) | Full web application business logic | Proxy interception, Turbo Intruder for race conditions, Repeater for state manipulation |
| **BOLABuster** (Research) | BOLA/IDOR vulnerabilities in APIs | LLM-powered endpoint dependency analysis and automated BOLA test case generation |
| **ZeroPath** (Automated) | Business logic, auth bypass, authz flaws | AI-native code analysis combining LLM with program analysis for semantic understanding |
| **Escape** (Automated API) | API business logic testing | Agentic testing engine that adapts paths based on discovered API structure |
| **Terra** (Automated) | Application-level business logic | AI agent swarm that probes and reasons through application flows like human pentesters |
| **Pynt** (API Security) | API business logic, OWASP API Top 10 | Automated API testing with business logic abuse detection |
| **OWASP ZAP** (Semi-automated) | Web application testing baseline | Active/passive scanning with manual business logic test augmentation |
| **Nuclei** (Template-based) | Known vulnerability patterns | Community-maintained templates for common business logic patterns |
| **Custom Abuse Case Frameworks** (Manual) | Domain-specific business logic | Threat modeling with abuse case development per OWASP methodology |
| **Imperva / AWS WAF Advanced** (Runtime) | Runtime business logic abuse detection | Behavioral baselining and stateful inspection to detect logic abuse patterns |

---

## Summary: Core Principles

### The Root Cause: Implicit Trust and Incomplete State Modeling

The entire spectrum of business logic vulnerabilities stems from a single fundamental property: **applications are state machines that incompletely model and enforce their own rules**. Every business application is, in formal terms, a Turing machine — with data (tape), access patterns (head), states (workflow positions), and transitions (business rules). Vulnerabilities emerge whenever the *implemented* state machine diverges from the *intended* state machine. This divergence manifests in three ways: (1) trusting input that should be verified (§1, §8, §9), (2) allowing transitions that should be forbidden (§2, §3, §6), and (3) failing to serialize operations that should be atomic (§4, §5).

### Why Incremental Patches Fail

Business logic vulnerabilities resist systematic elimination because they are **semantically defined** — you cannot identify them without understanding what the application is *supposed* to do, which no automated tool can fully capture. Each fix addresses a specific assumption violation, but the assumption space is combinatorially vast. Fixing a coupon race condition doesn't prevent a cart manipulation bug; patching a price tampering issue doesn't address a workflow bypass. Moreover, new features continually introduce new state transitions and business rules, each with their own assumption surface. The 59% year-over-year increase in API business logic attacks (2023→2024) reflects this expanding attack surface as applications grow in complexity.

### The Structural Solution

A principled defense requires operating at the **design level**, not the implementation level:

1. **Explicit State Machine Modeling**: Define all valid states and transitions formally, then enforce them through a centralized state management layer. Every endpoint verifies not just "is this user authenticated?" but "is this a valid transition from the current state?"

2. **Server-Side Authority for All Business Rules**: Never trust client-supplied values for prices, quantities, permissions, or state transitions. The server must be the single source of truth for all business-critical calculations and decisions.

3. **Atomic Operations with Serialization**: All check-then-act patterns must be atomic. Use database-level locking, optimistic concurrency control, or serializable transactions for any operation involving shared mutable state.

4. **Abuse Case Threat Modeling**: For every user story ("User can apply a coupon"), develop a corresponding abuse case ("Attacker applies the same coupon 1000 times simultaneously"). Integrate this into the development lifecycle, not as a post-hoc security review.

5. **Behavioral Monitoring**: Since logic flaws operate within legitimate application flows, detection requires understanding *normal* usage patterns and flagging statistical anomalies (e.g., 30 identical requests in 100ms, purchases at $0.01, workflow steps accessed out of order).

---

## References

- OWASP Top 10 for Business Logic Abuse (2025) — https://owasp.org/www-project-top-10-for-business-logic-abuse/
- OWASP Business Logic Vulnerability — https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability
- OWASP Web Security Testing Guide: Business Logic Testing — https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic
- CWE-840: Business Logic Errors — https://cwe.mitre.org/data/definitions/840.html
- PortSwigger Web Security Academy: Business Logic Vulnerabilities — https://portswigger.net/web-security/logic-flaws
- Rapid7 Top 10 Business Logic Attack Vectors Whitepaper — https://information.rapid7.com/top-10-business-logic-vectors-whitepaper.html
- HackerOne Top Business Logic Reports — https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPBUSINESSLOGIC.md
- Anota: Identifying Business Logic Vulnerabilities (arXiv 2024) — https://arxiv.org/pdf/2512.20705
- SlowMist 2024 Blockchain Security Report — https://www.slowmist.com/report/2024-Blockchain-Security-and-AML-Annual-Report(EN).pdf
- PayloadsAllTheThings: Business Logic Errors — https://swisskyrepo.github.io/PayloadsAllTheThings/Business%20Logic%20Errors/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
