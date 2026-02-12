# State Machine Violations — Mutation/Variation Taxonomy

---

## Classification Structure

Every stateful system — whether a protocol handshake, a multi-step web workflow, or a smart contract execution — relies on an implicit or explicit **state machine**: a set of states, transitions, and guards that constrain the sequence of operations. A **State Machine Violation** occurs when an attacker forces the system into a state, transition, or timing window that the designers assumed impossible, thereby breaking security invariants such as authentication, authorization, data integrity, or atomicity.

This taxonomy classifies the full attack surface along three orthogonal axes:

### Axis 1 — Violation Target (WHAT is violated)
The structural component of the state machine being subverted. This is the **primary axis** organizing the document body:

| §  | Target | Description |
|----|--------|-------------|
| §1 | Transition Sequence | The ordering of state transitions is subverted |
| §2 | State Guard / Precondition | A transition guard (check) is bypassed or weakened |
| §3 | Temporal Atomicity | The time window between check and effect is exploited |
| §4 | Object / Session State Binding | The binding between identity, session, and object state is broken |
| §5 | Protocol Framing & Negotiation | Protocol-level state machines are confused via framing or negotiation manipulation |
| §6 | Concurrency & Parallelism | Parallel execution paths create impossible state combinations |
| §7 | Lifecycle & Revocation | Token/credential lifecycle state is not properly tracked |
| §8 | Cryptographic State | Cryptographic negotiation or algorithm state is manipulated |

### Axis 2 — Discrepancy Type (WHY it works)
The nature of the mismatch or assumption violation that enables the attack:

| Type | Description |
|------|-------------|
| **Sequence Assumption** | System assumes steps will execute in a fixed order |
| **Atomicity Assumption** | System assumes a multi-step operation is indivisible |
| **Binding Assumption** | System assumes state is bound to the correct principal/object |
| **Completeness Assumption** | System assumes all mandatory steps will be performed |
| **Isolation Assumption** | System assumes concurrent operations cannot interfere |
| **Freshness Assumption** | System assumes tokens/credentials reflect current state |
| **Negotiation Trust** | System trusts client-supplied parameters in state negotiation |

### Axis 3 — Attack Scenario (WHERE it's weaponized)

| Scenario | Architectural Context |
|----------|----------------------|
| **Authentication Bypass** | Skipping or confusing authentication state transitions |
| **Authorization Escalation** | Reaching privileged states without proper authorization |
| **Financial/Logic Abuse** | Double-spend, limit overrun, payment bypass |
| **Data Integrity Violation** | Corrupting or forging trusted data through state confusion |
| **Denial of Service** | Forcing resource exhaustion via invalid state transitions |
| **Credential Forgery** | Creating or replaying credentials that should be invalid |
| **Protocol Downgrade** | Forcing weaker security parameters via negotiation manipulation |

---

## §1. Transition Sequence Violations

Attacks that subvert the expected ordering of state transitions — executing steps out of order, skipping mandatory steps, or injecting transitions that should be unreachable from the current state.

### §1-1. Step Skipping

The attacker omits one or more mandatory intermediate steps in a multi-step workflow, directly invoking a later step while the system fails to verify that all prerequisites were satisfied.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Endpoint Access** | Attacker navigates directly to a post-authentication or post-verification URL/API endpoint, bypassing the intermediate selection or verification step | Server does not enforce server-side state tracking of completed steps |
| **Role Selection Skip** | In authentication flows with a role-selection step (e.g., `POST /login` → `GET /role-selector`), attacker drops the role-selection request, causing the system to default to a privileged role | Default role is more privileged than intended |
| **MFA/2FA Step Skip** | Attacker completes primary authentication, then directly requests authenticated resources without completing the second-factor challenge | 2FA enforcement is checked only at the 2FA endpoint, not globally on authenticated routes |
| **Email/Phone Verification Skip** | Registration or account-change flow requires email/phone verification, but the attacker directly invokes the post-verification endpoint or uses a GraphQL/alternative endpoint that bypasses the check | Verification state is not enforced at the resource access layer |
| **Payment Gateway Skip** | In e-commerce checkout flows (cart → payment → confirmation), the attacker skips the payment step and directly invokes the order confirmation endpoint | Order completion is decoupled from payment verification |

**Example (Role Selection Skip):**
```
1. POST /login (credentials) → 302 to /role-selector
2. Attacker drops the /role-selector request
3. GET /admin → 200 OK (role defaults to "admin")
```

### §1-2. Out-of-Order Message Injection

The attacker sends protocol messages or API calls in an order not anticipated by the state machine, causing the server to process them against an incorrect internal state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-Authentication Command Injection** | Attacker sends messages intended for post-authentication phases during the unauthenticated handshake phase | Protocol implementation does not disconnect on unexpected messages (§5 cross-ref) |
| **Success Message Forgery** | Attacker sends a "success" status message (e.g., `SSH2_MSG_USERAUTH_SUCCESS`) in place of the expected "request" message, causing the server to advance to the authenticated state | Server state machine accepts peer-generated status messages without validating their origin |
| **Premature Data Transmission** | Attacker sends application data before the handshake or negotiation phase is complete | Server processes data frames regardless of handshake completion state |
| **Reverse-Direction State Forcing** | Attacker forces the state machine backward (e.g., reverting a "paid" order to "cart" status) via API calls that don't validate transition directionality | State transitions are not constrained to forward-only progression |

**Example (SSH Success Message Forgery — libssh):**
```
Client → Server: SSH2_MSG_USERAUTH_SUCCESS  (instead of SSH2_MSG_USERAUTH_REQUEST)
Server transitions to "authenticated" state without any credential verification
```

### §1-3. Transition Path Manipulation

The attacker exploits the existence of multiple valid paths through a state machine, selecting a path that bypasses security-critical transitions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Alternative Endpoint Routing** | Application exposes multiple API paths to reach the same destination state; one path omits a security check present in the canonical path | Security checks are implemented per-endpoint rather than per-state-transition |
| **Protocol Version Fallback** | Attacker forces use of an older protocol version whose state machine lacks security transitions added in newer versions | Server supports legacy protocol versions for backward compatibility |
| **Recovery/Reset Path Abuse** | Attacker exploits password-reset, account-recovery, or error-handling paths that transition to authenticated states with weaker checks | Recovery paths bypass standard authentication state machine |
| **GraphQL/Batch Endpoint Bypass** | GraphQL introspection or batch APIs expose mutations that reach protected states without traversing the standard workflow | API surface exposes state-changing operations without workflow enforcement |

---

## §2. State Guard / Precondition Bypass

Attacks that defeat the conditional checks (guards) that protect state transitions, allowing transitions that should be rejected.

### §2-1. Insufficient Guard Scope

The transition guard exists but does not cover all entry points to the protected state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Partial Path Enforcement** | Security check is applied to the primary endpoint but not to alternative endpoints reaching the same state | Multiple endpoints modify the same state object |
| **Client-Side Guard Reliance** | State transition guard is enforced only in client-side code (JavaScript, mobile app), with no server-side validation | Server trusts that the client enforces the workflow |
| **Middleware Ordering Gap** | Authentication/authorization middleware executes after a state-changing operation has already begun, creating a window where the operation proceeds without authorization | Middleware pipeline ordering does not match the logical dependency order |
| **Microservice Trust Boundary** | Internal microservice accepts state-change requests without re-validating that the calling service's workflow state is correct | Inter-service calls lack workflow context propagation |

### §2-2. Guard Condition Manipulation

The attacker satisfies the guard by manipulating the data it evaluates, rather than by legitimately reaching the expected state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Parameter Tampering** | Attacker modifies request parameters (price, quantity, role, status) to satisfy or bypass guard checks | Guard evaluates client-supplied data without server-side validation |
| **Mass Assignment / Object State Injection** | Attacker injects unexpected fields (e.g., `"role":"admin"`, `"is_superuser":true`) into API payloads, directly overwriting internal state properties | Framework auto-binds request fields to model properties without allowlisting |
| **Data Type Smuggling** | Attacker sends values in unexpected types (e.g., `"1e4"` string instead of integer `1`, `"true"` string instead of boolean) to bypass type-sensitive guards | Loose type coercion in guard evaluation |
| **Null/Default State Exploitation** | Attacker exploits uninitialized or default state values (e.g., null, empty array, zero) that incorrectly satisfy guard conditions | Guard treats uninitialized state as a valid passing condition |

**Example (Mass Assignment):**
```json
// Normal user update request
PATCH /api/users/me
{"name": "attacker"}

// State injection attack
PATCH /api/users/me
{"name": "attacker", "is_superuser": true, "role": "admin"}
```

### §2-3. Guard Timing Exploitation

The guard check is correct but can be satisfied at a different time than when the transition actually executes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **TOCTOU (Time-of-Check to Time-of-Use)** | Guard checks a condition at time T₁, but the state-changing operation executes at time T₂, and the condition changes between T₁ and T₂ | Check and use are not within the same atomic transaction |
| **Stale Token Acceptance** | Guard validates a token/credential that was valid at issuance but has since been revoked, expired, or superseded | Guard checks token signature/format but not current revocation status |
| **Cached Authorization Bypass** | Guard evaluates cached authorization decisions that no longer reflect the current permission state | Authorization results are cached without invalidation on state changes |

---

## §3. Temporal Atomicity Violations

Attacks that exploit the non-atomic nature of state transitions — the fleeting intermediate states that exist between the beginning and completion of a multi-step operation.

### §3-1. Race Condition Exploitation (Limit Overrun)

The classic race condition: multiple concurrent requests pass the same guard check before any of them apply their state mutation, causing limits to be exceeded.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Counter/Balance Overrun** | Multiple concurrent requests each pass a balance/inventory/rate check, then each deducts from the same counter | Check and deduction are not atomic; no row-level locking or serializable transaction |
| **Coupon/Code Multi-Redemption** | Multiple concurrent requests each verify a single-use code is unused, then each marks it as used | Code validity check and usage marking are separate operations |
| **Vote/Rating Manipulation** | Concurrent requests bypass rate limits on voting, rating, or similar one-per-user operations | Per-user uniqueness is enforced in application logic rather than database constraints |

**Example (Single-Packet Attack for Limit Overrun):**
```
1. Bundle 20-30 "apply discount" requests into a single TCP packet (HTTP/2)
2. All requests arrive within <1ms, all read "discount not applied"
3. All 20-30 requests apply the discount → 20-30x value extracted
```

### §3-2. Partial Construction Races

The attacker exploits the intermediate state of a partially-constructed object — accessing it before all its security properties have been initialized.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Uninitialized Security Property** | Object is created in the database with default/null values for security-critical fields, then a concurrent request reads the object before those fields are populated | Object creation and security-field population are separate database operations |
| **Incomplete Registration Exploitation** | User account is partially created (email unverified, role unassigned) but accessible through concurrent requests before the creation flow completes | Account existence check succeeds before all security attributes are set |
| **Default Privilege Window** | System initializes sessions or objects with maximum privileges, then downgrades; concurrent requests during the window inherit the initial privileges | Privilege assignment follows a "start high, restrict later" pattern |

**Example (Default Privilege Window):**
```
Thread 1: POST /login → session.role = "admin" (default) → role = lookup(user) → session.role = "user"
Thread 2: GET /admin-panel (during the window between default assignment and downgrade) → 200 OK
```

### §3-3. Multi-Endpoint Collision

Concurrent requests to different endpoints that share state create impossible state combinations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Endpoint Token Misdirection** | Concurrent email-change and email-verify requests cause confirmation tokens to be associated with the wrong email address | Token generation and email-address binding are separate non-atomic operations |
| **Simultaneous State Forking** | Concurrent requests to different endpoints fork the same object into conflicting states (e.g., both "approved" and "rejected") | No mutual exclusion on state-changing operations for the same object |
| **Mixed Data Source Race** | Application reads the token from the database but the associated email from an instance variable; concurrent requests cause a mismatch between the two | Different attributes of the same logical state are stored in different locations |

### §3-4. Deferred / Asynchronous Collision

Race conditions that exploit asynchronous or batch-processed operations, where the race window can span minutes or hours.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Background Job Race** | Requests submitted minutes apart collide when processed by the same background worker, producing conflicting state mutations | Background processing batches operations without per-object locking |
| **Event Queue Reordering** | Events processed out of their causal order by message queues or event-driven systems, causing later events to overwrite corrections from earlier events | Event processing lacks causal ordering guarantees |
| **Distributed System Split-Brain** | Network partitions or replication lag cause different nodes to accept conflicting state transitions for the same object | Eventual consistency model without conflict resolution for security-critical state |

---

## §4. Object / Session State Binding Violations

Attacks that break the assumed binding between a state machine instance and its owning principal (user, session, object).

### §4-1. Session State Confusion

The attacker manipulates session state to inherit or assume another principal's state machine position.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session Fixation** | Attacker forces the victim to use a pre-determined session ID, then inherits the victim's authenticated state when the victim logs in | Application does not regenerate session IDs upon authentication |
| **Cross-Session State Leakage** | Server reuses session state structures between users, causing one user's workflow state to leak into another's session | Session cleanup is incomplete upon logout or timeout |
| **Session Puzzling / Variable Overloading** | Multiple application features use the same session variable for different purposes; attacker triggers one feature to set the variable, then exploits another feature that reads it | Session variables are shared across unrelated workflows |

**Example (Session Fixation):**
```
1. Attacker obtains session ID: JSESSIONID=abc123
2. Attacker sends victim a link: https://target.com/login?JSESSIONID=abc123
3. Victim authenticates → server associates abc123 with authenticated state
4. Attacker uses abc123 → inherits victim's authenticated session
```

### §4-2. Token/Credential State Unbinding

The attacker exploits tokens or credentials that are not properly bound to their intended context.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Context Token Replay** | Token issued for context A (e.g., password-reset) is accepted in context B (e.g., email-verification) | Token lacks audience/purpose binding claims |
| **Cross-User Token Substitution** | Attacker substitutes their own token/order-ID/reference-number for another user's, and the system processes it against the attacker's session | Token is not cryptographically bound to the issuing session/user |
| **OAuth State Parameter Absence** | OAuth flow lacks a `state` parameter or uses a predictable one, allowing login CSRF where the victim is logged into the attacker's account | OAuth client does not validate the state parameter on callback |
| **SAML Assertion Replay** | Attacker replays a captured SAML assertion after it should have expired or been consumed | Service provider does not enforce one-time-use or temporal constraints on assertions |

### §4-3. Stateless Token State Drift

When stateless tokens (JWTs, signed cookies) diverge from the actual server-side state they represent.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-Revocation Token Use** | JWT or signed cookie remains valid after the user logs out, is banned, or changes password | No server-side revocation check; token validity is purely self-contained |
| **Stale Claim Exploitation** | Token claims (roles, permissions, email) become outdated as the user's server-side state changes, but the token is not refreshed | Long-lived tokens with no claim-refresh mechanism |
| **Algorithm Confusion State** | Attacker changes the JWT header algorithm (e.g., RS256 → HS256), causing the server to verify the token using the wrong key/algorithm | Server dynamically selects algorithm from the token header rather than enforcing a fixed algorithm |

---

## §5. Protocol Framing & Negotiation State Violations

Attacks that exploit the state machines of network protocols — the handshake, negotiation, and framing rules that govern how protocol messages are sequenced and interpreted.

### §5-1. Handshake State Machine Confusion

The attacker sends protocol messages that violate the expected handshake state machine, causing the server to enter an incorrect state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Early CCS Injection (TLS)** | Attacker injects a ChangeCipherSpec message before the key exchange is complete, forcing use of a zero-length or weak master secret | TLS implementation accepts CCS at any handshake state rather than only at the expected point |
| **Pre-Auth Message Injection (SSH)** | Attacker sends post-authentication SSH messages (channel-open, exec) during the unauthenticated phase | SSH server processes message types without checking the current authentication state |
| **DTLS Message Reordering** | Attacker reorders DTLS handshake messages to complete a handshake without client authentication or without ChangeCipherSpec | DTLS implementation accepts out-of-order messages without enforcing sequencing constraints |
| **WebSocket Upgrade Confusion** | Attacker manipulates the HTTP-to-WebSocket upgrade handshake to establish a WebSocket connection without proper authentication or cross-origin validation | WebSocket upgrade inherits HTTP session cookies without CSRF protection |

**Example (TLS Early CCS — CVE-2014-0224):**
```
Client                          MITM                         Server
  |--- ClientHello --------------->|--- ClientHello ------------>|
  |<-- ServerHello + Certificate --|<-- ServerHello + Cert ------|
  |                                |--- CCS (injected) -------->|  ← forces zero-key
  |--- CCS (injected) ----------->|                             |
  |--- Finished (zero-key) ------>|--- Finished (zero-key) ---->|
  |<-- Finished ------------------|<-- Finished ----------------|
  // All traffic now encrypted with attacker-known zero-length key
```

### §5-2. Protocol Frame State Abuse

The attacker sends protocol frames that are syntactically valid but violate the expected stream or connection state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTTP/2 Rapid Reset** | Attacker opens streams and immediately resets them via RST_STREAM, creating unbounded stream churn that exhausts server resources | Server allocates resources on stream creation before RST_STREAM is processed |
| **HTTP/2 Invalid Frame on Half-Closed Stream** | Attacker sends DATA or HEADERS frames on streams in half-closed state, forcing the server to detect invalid state and reset | Server performs expensive validation before rejecting invalid frames |
| **SMTP/IMAP Command Injection** | Attacker injects CRLF characters to break out of the current SMTP command context, injecting new commands that the server processes against the established session state | Server does not sanitize user-supplied data for protocol control characters |
| **FTP Bounce (PORT Command Abuse)** | Attacker issues PORT commands specifying a third-party IP/port, causing the FTP server to initiate data connections to arbitrary hosts | FTP server does not validate that PORT targets match the control connection source |

### §5-3. Negotiation Downgrade

The attacker manipulates the negotiation phase to force weaker security parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cryptographic Algorithm Downgrade** | Attacker modifies ClientHello/ServerHello to remove strong ciphersuites, forcing selection of weak or broken ones | Negotiation integrity is not protected until after ciphersuite selection |
| **Key Length Downgrade (KNOB)** | Attacker intercepts Bluetooth entropy negotiation and forces encryption key length to 1 byte, enabling trivial brute force | Bluetooth specification does not protect entropy negotiation integrity |
| **Protocol Version Downgrade** | Attacker manipulates version negotiation to force use of a protocol version with known state machine vulnerabilities | Server supports legacy versions without downgrade detection mechanisms |
| **Feature Stripping** | Attacker strips security-relevant extensions or features (e.g., TLS extensions, HTTP security headers) from negotiation messages | Feature negotiation occurs before integrity protection is established |

---

## §6. Concurrency & Parallelism State Violations

Attacks that exploit the interaction between concurrent state machine instances or parallel execution paths. While §3 focuses on temporal gaps within a single operation, §6 addresses cross-operation and cross-instance concurrency.

### §6-1. Concurrent Workflow Order Bypass (CWOB)

Exploiting parallelism in distributed workflows to execute step N before step N-1 has completed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Distributed Orchestration Gap** | In a multi-service architecture, the attacker submits a payment-completion request before the inventory-check service has finished processing | Services process steps independently without a central orchestrator enforcing order |
| **Sub-State Race Within Single Request** | Within a single request, the framework executes internal stages sequentially; the attacker fires a concurrent request that reads intermediate sub-state | Internal request processing is not atomic with respect to concurrent requests |
| **Pipeline Parallelism Exploitation** | The attacker exploits the fact that stages of a processing pipeline can be at different states for different requests simultaneously | Pipeline stages share mutable state without synchronization |

### §6-2. Double-Action Exploitation

Multiple concurrent requests all trigger the same state-changing action, which should be triggered at most once.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double-Spend** | Two concurrent withdrawal/transfer requests are both processed against the same balance, each deducting the same funds | Balance check and deduction are not in a serializable transaction |
| **Duplicate Object Creation** | Concurrent requests create duplicate entities that should be unique (users, orders, invitations), producing conflicting state | Uniqueness enforcement relies on application-level checks rather than database constraints |
| **Parallel Privilege Grant** | Concurrent requests both grant the same privilege, or one grants while the other checks, creating privilege states that bypass single-grant controls | Privilege granting lacks mutual exclusion |

### §6-3. Smart Contract Reentrancy

A specialized concurrency violation in blockchain environments where external calls re-enter the calling function before state updates complete.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Single-Function Reentrancy** | Malicious contract's fallback function recursively calls the vulnerable function before the balance update, draining funds | State update (balance deduction) occurs after the external call |
| **Cross-Function Reentrancy** | Malicious contract calls a different function that shares state with the vulnerable function, exploiting the shared stale state | Multiple functions share a state variable that is updated non-atomically |
| **Cross-Contract Reentrancy** | Attack spans multiple contracts, where one contract's callback triggers a function in a third contract that reads stale state from the vulnerable contract | Inter-contract calls create implicit shared state without synchronization |

**Example (The DAO Reentrancy — $60M theft):**
```solidity
function withdraw(uint amount) {
    require(balances[msg.sender] >= amount);  // Check
    msg.sender.call{value: amount}("");        // External call → attacker re-enters
    balances[msg.sender] -= amount;            // State update (too late)
}
```

---

## §7. Lifecycle & Revocation State Violations

Attacks that exploit failures in tracking the lifecycle states of tokens, credentials, sessions, and objects — using them after they should have been invalidated.

### §7-1. Revocation Failure

The system fails to enforce state transitions to the "revoked" or "invalidated" state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-Logout Session Use** | Session token remains valid after the user explicitly logs out | Server does not invalidate the session on the server side, or relies on client-side token deletion |
| **Stateless Token Non-Revocation** | JWT or similar stateless token cannot be revoked because there is no server-side revocation list | Architecture chose pure stateless tokens without a revocation mechanism |
| **OAuth Refresh Token Persistence** | Revoked OAuth refresh tokens continue to be accepted because the revocation is not propagated to all token validation endpoints | Distributed token validation without consistent revocation propagation |
| **Password Change Token Survival** | All existing sessions and tokens remain valid after a password change, allowing an attacker who stole a token before the change to continue using it | Password change does not trigger global token invalidation |

### §7-2. Lifecycle Transition Bypass

The attacker forces an object through lifecycle transitions that should be irreversible or conditional.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **State Regression** | Attacker reverts an object from a terminal or advanced state back to an earlier state (e.g., "completed" order → "pending", "banned" user → "active") | API does not enforce forward-only state transitions |
| **Resurrection After Deletion** | Attacker accesses or restores a soft-deleted resource, exploiting the gap between "deleted" flag and actual cleanup | Soft deletion does not fully enforce access restrictions |
| **Expired Token Acceptance** | System continues to accept tokens past their expiration time due to clock skew, lenient validation, or grace periods | Token validation allows excessive clock-skew tolerance |

### §7-3. One-Time Use Violation

Tokens or operations intended for single use are reused.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Nonce Replay** | Attacker replays a captured nonce, one-time password, or challenge-response after it has already been consumed | Consumed nonces are not recorded or checked |
| **SAML Assertion Replay** | SAML assertion is presented multiple times to the Service Provider | SP does not maintain a consumed-assertion cache |
| **Idempotency Key Abuse** | Attacker reuses or predicts idempotency keys to replay or manipulate transaction outcomes | Idempotency keys are not scoped per-client or use predictable values |

---

## §8. Cryptographic State Violations

Attacks that manipulate the cryptographic aspects of state machine negotiation — algorithms, keys, and parameters.

### §8-1. Algorithm State Confusion

The attacker manipulates which cryptographic algorithm the system uses for verification.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JWT Algorithm Switching (RS256→HS256)** | Attacker changes JWT header from RS256 to HS256, causing the server to treat the public key as an HMAC secret | Server selects algorithm from the JWT header rather than enforcing a fixed algorithm |
| **JWT "none" Algorithm** | Attacker sets the algorithm to "none", and the server accepts the token as valid without any signature | Library treats "none" as a valid algorithm |
| **SAML Signature Wrapping** | Attacker restructures the XML document to move the signed element while inserting a malicious unsigned element that the application processes | XML signature verification and application data extraction use different tree traversal paths |
| **XML Canonicalization Comment Injection** | Attacker inserts XML comments into SAML assertions that are stripped during canonicalization but affect application-level parsing | Canonicalization algorithm discards comments, but application parser interprets them |

### §8-2. Key/Parameter State Manipulation

The attacker manipulates the cryptographic keys or parameters established during negotiation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Zero-Key Establishment** | MITM injects early CCS to force derivation of session keys from a zero-length pre-master secret | Implementation derives keys from whatever state is available rather than validating completeness |
| **Entropy Downgrade** | Attacker forces the minimum allowable entropy for encryption keys (e.g., 1-byte Bluetooth keys) | Protocol specification allows entropy negotiation without integrity protection |
| **Key Renegotiation Attack** | Attacker triggers key renegotiation mid-session to inject plaintext into the encrypted stream | Renegotiation is not cryptographically bound to the existing session |
| **Session Resumption Bypass** | Attacker exploits TLS session resumption to authenticate with a certificate that was valid during the original session but has since been revoked or changed | Resumption does not re-validate the full certificate chain |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Authentication Bypass** | Any multi-step auth flow | §1-1 + §1-2 + §2-1 + §5-1 |
| **Authorization Escalation** | Role-based or attribute-based access control | §1-3 + §2-2 + §3-2 + §4-1 |
| **Financial/Logic Abuse** | E-commerce, payments, crypto | §1-1 + §3-1 + §6-2 + §6-3 |
| **Data Integrity Violation** | Multi-endpoint APIs, form workflows | §3-3 + §4-2 + §3-4 |
| **Denial of Service** | Protocol-level services | §5-2 + §5-3 + §3-4 |
| **Credential Forgery** | Token-based auth (JWT, SAML, OAuth) | §4-3 + §7-3 + §8-1 |
| **Protocol Downgrade** | TLS, Bluetooth, SSH | §5-1 + §5-3 + §8-2 |

---

## CVE / Bounty Mapping (2014–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-2 (SSH Success Forgery) | CVE-2018-10933 (libssh) | Critical auth bypass. Attacker sends `SSH2_MSG_USERAUTH_SUCCESS` → unauthenticated channel creation |
| §1-2 + §5-1 (Pre-Auth Injection) | CVE-2025-32433 (Erlang/OTP SSH) | CVSS 10.0. Unauthenticated RCE via injecting post-auth messages during handshake |
| §5-1 (Early CCS) | CVE-2014-0224 (OpenSSL) | MITM decryption of all TLS traffic via zero-key establishment |
| §5-2 (HTTP/2 Rapid Reset) | CVE-2023-44487 | Record-breaking DDoS: 398M rps (Google). Unbounded stream creation via RST_STREAM abuse |
| §5-3 (Bluetooth KNOB) | CVE-2019-9506 | 1-byte entropy negotiation. Affects 38+ devices across all major BT versions |
| §8-2 (Session Resumption) | CVE-2025-68121 (Go TLS) | Auth bypass via mutated CAs between handshakes in TLS session resumption |
| §1-1 + §5-1 (DTLS Auth Bypass) | CVE-2020-27216 area (JSSE DTLS) | Complete client authentication bypass via out-of-order DTLS messages |
| §6-3 (Reentrancy) | The DAO Hack (2016) | $60M ETH stolen. Single-function reentrancy in withdraw() |
| §6-3 (Reentrancy) | Curve Finance (2023) | ~$70M stolen. Vyper compiler bug enabled reentrancy in DeFi pools |
| §8-1 (SAML Signature) | SAMLStorm (2025, xml-crypto) | Zero-day: forged SAML responses → admin account access across Node.js SAML stacks |
| §8-1 (SAML Comment Injection) | CVE-2017-11427 through CVE-2017-11430 | Auth bypass across OneLogin, ruby-saml, saml2-js libraries |
| §2-2 (Mass Assignment) | CVE-2024-13275 (Langflow) | Privilege escalation to superadmin via `is_superuser` field injection |
| §3-1 (Limit Overrun) | Multiple GitLab / HackerOne bounties | Discount/coupon multi-redemption, vote manipulation via single-packet attack |
| §1-1 (MFA Skip) | Azure AuthQuake (2024) | Silent brute-force of MFA via misconfigured timer, reported by Oasis Security |
| §1-1 (Payment Skip) | CVE-2024-28080 area (Gitblit SSH) | SSH auth bypass via public key state machine flaw in Apache MINA SSHD |
| §5-2 (FTP Bounce) | Historical (RFC 2577) | Port scanning, SMTP relay, firewall bypass via FTP PORT command abuse |
| §3-4 (Distributed TOCTOU) | AWS DynamoDB DNS Outage (2025) | Major US-EAST-1 outage from stale DNS plans applied after newer ones were cleaned |
| §2-3 (Kernel TOCTOU) | CVE-2024-30088 (Windows Kernel) | Local privilege escalation via kernel-level TOCTOU race condition |
| §2-3 (VMware TOCTOU) | CVE-2025-22224 (VMware ESXi) | TOCTOU → out-of-bounds write. Actively exploited in the wild |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Turbo Intruder** (Offensive) | Web race conditions (§3, §6) | Single-packet attack: bundles 20-30 requests in one TCP packet for sub-1ms delivery |
| **Burp Suite Repeater** (Offensive) | Sequential state bypass (§1) | Send group of requests in parallel with configurable timing |
| **TLS-Attacker** (Research/Offensive) | TLS state machine (§5-1, §8) | Arbitrary TLS workflow trace construction; tests for CCS injection, reordering, truncation |
| **statelearner** (Research) | Protocol state machines (§5) | Automata learning via LearnLib; infers implementation state machines from black-box interaction |
| **dtls-fuzzer** (Research) | DTLS state machine (§5-1) | Protocol state machine learning and fuzzing for DTLS servers and clients |
| **StateAFL** (Research) | Stateful network protocols (§5) | Greybox fuzzer using memory-snapshot-based state inference |
| **i7Fuzzer** (Research) | Stateful protocols (RTSP, MQTT) (§5) | LSTM-guided mutation for protocol message fuzzing |
| **SSGFuzz** (Research) | Stateful protocol implementations (§5) | State-significance-guided fuzzing prioritizing high-risk states |
| **ProtocolGPT** (Research) | Protocol state inference (§5) | LLM-powered state machine inference from protocol implementations |
| **Slither / Mythril** (Offensive) | Smart contract reentrancy (§6-3) | Static analysis and symbolic execution for Solidity state violations |
| **OpenZeppelin ReentrancyGuard** (Defensive) | Smart contract reentrancy (§6-3) | Mutex-based reentrancy prevention modifier for Solidity |
| **OWASP ZAP** (Offensive) | Web workflow state (§1, §2) | Active scanning for authentication state machine flaws |
| **Nmap ssl-ccs-injection** (Offensive) | TLS CCS injection (§5-1) | Detects CVE-2014-0224 vulnerability in TLS implementations |
| **ProFuzzBench** (Research) | Benchmark for stateful protocol fuzzers (§5) | Standardized evaluation framework for comparing stateful fuzzing tools |

---

## Summary: Core Principles

### The Root Cause: Implicit State Machines

The fundamental property that makes this entire mutation space possible is that **most systems implement state machines implicitly** — through scattered conditional checks, database flags, session variables, and middleware ordering — rather than as explicit, formally verifiable state machine definitions. When the state machine exists only in the developer's mental model, every implementation gap becomes a potential violation vector. Protocol implementations embed state machines in complex code paths where message handling functions may not rigorously validate the current state before processing; web applications distribute state across cookies, databases, session stores, and in-memory variables without a single authoritative state representation; smart contracts update state after external calls rather than before.

### Why Incremental Patches Fail

State machine violations are resistant to incremental patching because each fix addresses a **specific transition or guard** while leaving the underlying implicit architecture unchanged. Patching the CCS injection in OpenSSL does not prevent the next unexpected-message-ordering vulnerability. Adding a check for one MFA bypass path does not cover the alternative endpoint discovered next month. The attack surface is not a list of bugs — it is a structural property of how the system represents and enforces state. Every new endpoint, protocol extension, or microservice interaction adds new transitions that must be validated against the complete state machine, and implicit machines make complete validation impossible.

### The Structural Solution

The structural solution is **explicit state machine enforcement**: defining allowed states, transitions, and guards as first-class data structures (or formal specifications) that are the single source of truth for what transitions are permitted. At the protocol level, this means state-aware message dispatchers that reject any message not expected in the current state. At the application level, this means workflow engines or state machine libraries that centralize transition logic rather than distributing it across endpoints. At the concurrency level, this means atomic state transitions via serializable database transactions, optimistic locking, or CRDTs rather than check-then-act patterns. At the cryptographic level, this means fixed algorithm enforcement and transcript binding that makes negotiation tampering detectable. The gap between current practice and this ideal — the gap between implicit and explicit state machines — is the territory this taxonomy maps.

---

## References

- PortSwigger Research, "Smashing the state machine: the true potential of web race conditions" (Black Hat USA 2023 / DEF CON 31)
- Flatt Security, "Beyond the Limit: Expanding single-packet race condition with first sequence sync" (2024)
- OWASP, "Top 10 for Business Logic Abuse" — BLA2 (CWOB), BLA3 (OSM), BLA4 (Sequential State Bypass) (2025)
- de Ruiter & Poll, "Protocol State Fuzzing of TLS Implementations" (USENIX Security 2015)
- Fiterau-Brostean et al., "Analysis of DTLS Implementations Using Protocol State Fuzzing" (USENIX Security 2020)
- Maehren et al., "Learning TLS State Machines" (USENIX Security 2025)
- CVE-2014-0224 (OpenSSL CCS Injection), CVE-2018-10933 (libssh auth bypass), CVE-2023-44487 (HTTP/2 Rapid Reset)
- CVE-2025-32433 (Erlang/OTP SSH RCE), CVE-2025-68121 (Go TLS session resumption), CVE-2019-9506 (Bluetooth KNOB)
- CVE-2025-22224 (VMware ESXi TOCTOU), CVE-2024-30088 (Windows Kernel TOCTOU)
- WorkOS, "SAMLStorm: Critical Authentication Bypass in xml-crypto" (2025)
- OWASP, "SC05:2025 - Reentrancy" (Smart Contract Top 10)
- Antonioli et al., "Key Negotiation Downgrade Attacks on Bluetooth and Bluetooth Low Energy" (ACM TOPS 2020)
- Cloudflare, "HTTP/2 Rapid Reset: deconstructing the record-breaking attack" (2023)
- Imperva, "MadeYouReset: Turning HTTP/2 Server Against Itself" (2024)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
