# Web Application Logic Bug Mutation/Variation Taxonomy

> **Scope**: Quirky, hard-to-classify web application bugs that arise from flawed conditional logic, implicit assumptions, semantic misunderstandings, and state mismanagement — bugs that don't fit neatly into standard injection/XSS/SSRF categories. These are the bugs that exploit *how developers think* rather than *what parsers accept*.

---

## Classification Structure

This taxonomy organizes logic bugs along three axes:

### Axis 1 — Broken Assumption (PRIMARY)
What implicit developer assumption is violated? This is the structural root cause — the mental model gap that creates the vulnerability. This axis structures the main body of the document.

### Axis 2 — Manipulation Primitive (CROSS-CUTTING)
How does the attacker trigger the assumption failure? This describes the concrete action taken.

| Primitive | Description |
|-----------|-------------|
| **Omission** | Removing, emptying, or not sending an expected field/parameter/step |
| **Substitution** | Replacing an expected value with a different type, encoding, or semantic equivalent |
| **Reordering** | Changing the sequence of operations, steps, or requests |
| **Duplication** | Sending the same operation multiple times, concurrently or sequentially |
| **Injection** | Adding unexpected extra fields, parameters, or values |
| **Coercion** | Forcing type conversion or semantic reinterpretation of existing values |

### Axis 3 — Exploitation Context (MAPPING)
Where does this bug manifest in a real application?

| Context | Description |
|---------|-------------|
| **Authentication** | Login, password reset, MFA, SSO flows |
| **Authorization** | Access control, privilege boundaries, role management |
| **Financial** | Payments, pricing, discounts, credits, refunds |
| **State Management** | Sessions, workflows, multi-step processes |
| **Data Integrity** | User profiles, records, configurations |
| **Rate/Resource Control** | Limits, quotas, anti-automation |

---

## §1. Conditional Validation Bypass — "Only Check If Present"

The developer assumes that validation runs on every request, but the validation logic is guarded by a presence check (`if field exists, then validate`). Omitting or emptying the field causes the entire validation block to be skipped.

### §1-1. Field Omission Bypass

The most canonical form: a validation routine is wrapped in a conditional that checks whether the field is present or non-empty before applying rules. Removing the field from the request entirely (or sending it as empty/null) causes the server to skip validation and proceed with a default or unchanged value.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Password-empty bypass** | Password validation only runs when `password` field is non-empty; sending empty string or omitting it skips strength/correctness checks | Server updates user record without re-validating password, or accepts login with empty credential |
| **Optional-field privilege injection** | Admin-only fields (e.g., `role`, `isAdmin`) are validated only when present in the request body; omitting them causes the server to accept whatever was auto-bound | Framework uses mass assignment / auto-binding (§5-1) |
| **CAPTCHA omission** | CAPTCHA verification only fires when `captcha_response` parameter exists; removing it from POST data bypasses the check entirely | Server does not enforce CAPTCHA presence server-side |
| **MFA code omission** | 2FA/OTP validation only executes when `otp` or `code` parameter is in the request; omitting it skips the second factor | Application checks `if (req.body.otp) { verify(otp) }` instead of `if (user.requires_2fa) { ... }` |
| **Content-Type dependent parsing** | Sending request with no `Content-Type` or an unexpected one (e.g., `text/plain` instead of `application/json`) causes the parser to skip body validation entirely | WAF or middleware only inspects bodies with expected Content-Types |

### §1-2. Null/Empty/Undefined Confusion

Different from field omission — the field *is* present but carries a semantically "empty" value that the validation logic misinterprets.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON null bypass** | Sending `{"password": null}` passes the `if (field in body)` check but fails the `if (password)` truthiness check, causing validation to be skipped via a different branch | Language treats `null` as present-but-falsy |
| **Empty array bypass** | Sending `{"ids": []}` passes existence checks but causes `forEach` validation loops to execute zero times, skipping all validation | Validation iterates over input rather than checking a fixed schema |
| **Undefined vs null differential** | In JavaScript, `req.body.field === undefined` (omitted) vs `req.body.field === null` (explicitly null) trigger different code paths; one path has validation, the other doesn't | Express/Node.js with inconsistent null handling |
| **Empty string type coercion** | `""` is falsy in most languages; if validation checks `if (value)` before `validate(value)`, empty strings skip validation but may still be stored | Database accepts empty strings as valid entries |
| **Zero-value bypass** | Numeric field set to `0` passes presence checks but is falsy, skipping `if (amount) { validateAmount(amount) }` | Relevant in pricing/quantity contexts (§7-1) |

---

## §2. Type Confusion and Coercion — "I Expected a String"

The developer assumes inputs will always be of the expected type. Sending a different type (array instead of string, object instead of scalar, number instead of string) causes unexpected behavior in comparison, validation, or storage operations.

### §2-1. Loose Comparison Type Juggling

Languages with loose typing (PHP, JavaScript) perform automatic type coercion during comparisons, producing `true` for semantically unrelated values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PHP `==` magic hash** | Password hashes starting with `0e` followed by digits (e.g., `0e462097431906509019562988736854`) are interpreted as `0` in scientific notation; `"0e..." == "0e..."` evaluates to `true` regardless of actual hash content | Application uses `==` instead of `===` for hash comparison |
| **PHP `==` string-to-int** | `"0" == false`, `"" == false`, `"0" == null` all evaluate inconsistently; `0 == "any_string"` is `true` in older PHP versions | Loose comparison in authentication or authorization checks |
| **JavaScript `==` coercion** | `[] == false` is `true`, `"" == 0` is `true`, `null == undefined` is `true`; these can bypass authorization checks that use loose equality | Authorization logic uses `==` instead of `===` |
| **JSON number precision** | Sending a very large integer in JSON (e.g., `{"id": 99999999999999999999}`) may overflow to a different value after parsing, matching a different user's ID | 64-bit integer precision limits in JavaScript's `Number` type |
| **Boolean coercion bypass** | Sending `{"admin": "true"}` (string) or `{"admin": 1}` (integer) when the server expects boolean but uses loose comparison to check | Inconsistent type handling between API layer and business logic |

### §2-2. Parameter Type Switching

Sending a structurally different type than expected to exploit type-dependent code paths.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Array instead of string** | Sending `param[]=value` instead of `param=value` causes string operations (regex, `indexOf`, `===`) to fail or behave unexpectedly, potentially bypassing validation | PHP/Rails/Node.js parameter parsing auto-converts `param[]` to array |
| **Object instead of scalar** | Sending `{"password": {"$gt": ""}}` (NoSQL injection variant) or `{"field": {"toString": ...}}` to trigger prototype method calls | MongoDB query operators, JavaScript prototype chain |
| **String instead of number** | Sending `"quantity": "1e2"` (scientific notation) which parses to `100`, or `"amount": "0xff"` (hex) which parses to `255` | Language-specific numeric parsing accepts multiple formats |
| **Nested object injection** | Sending `{"user": {"role": "admin"}}` when the server expects `{"user": "username"}` — the nested object may be partially merged into the user record | ORM/framework auto-merges nested parameters |

### §2-3. Encoding and Representation Confusion

The *same semantic value* represented differently across system boundaries causes mismatched interpretation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unicode normalization bypass** | Characters like `ⓐⓓⓜⓘⓝ` (circled letters) normalize to `admin` after NFKC normalization; a blocklist check before normalization fails to catch it | Validation happens before Unicode normalization (§6-3) |
| **Case mapping confusion** | Turkish locale `İ` (U+0130) lowercases to `i` in Turkish but to `i̇` elsewhere; German `ß` uppercases to `SS`; used to bypass case-insensitive comparisons | Application performs case-insensitive matching with locale-dependent functions |
| **Overlong UTF-8 encoding** | Encoding `/` as `%c0%af` (overlong 2-byte) or `%e0%80%af` (overlong 3-byte) may bypass path-based validation while the backend normalizes it back to `/` | WAF/proxy validates raw bytes, backend normalizes UTF-8 |
| **Homoglyph substitution** | Using visually identical characters from different Unicode blocks (Cyrillic `а` vs Latin `a`) to bypass string-matching blocklists or create misleading identifiers | Validation uses byte-level comparison without Unicode normalization |
| **Numeric representation variance** | IP address `127.0.0.1` represented as `2130706433` (decimal), `0x7f000001` (hex), `0177.0.0.1` (octal), or `127.1` (abbreviated) bypasses blocklists | SSRF/access-control filters compare strings, not parsed addresses |

---

## §3. State Machine Violations — "Users Will Follow the Flow"

The developer assumes users will complete multi-step processes in the designed order. Attackers skip steps, repeat steps, or access endpoints out of sequence to reach states that should be unreachable.

### §3-1. Step Skipping

Directly accessing a later step in a multi-step workflow without completing prerequisites.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-authentication direct access** | After the login page, the application has a role-selection or MFA page; directly navigating to `/dashboard` after password verification skips role-selection/MFA | Server checks "is authenticated?" but not "has completed all required steps?" |
| **Payment step bypass** | In a checkout flow (cart → address → payment → confirm), directly submitting to the `/confirm` endpoint skips payment processing | Order completion doesn't verify payment was actually processed |
| **Email verification skip** | Accessing protected features immediately after registration without clicking the verification link; the server checks `is_logged_in` but not `is_email_verified` | Session is created at registration, not at verification |
| **Wizard completion skip** | Multi-step forms (insurance application, KYC) can be completed by submitting the final step directly with required fields | Each step doesn't validate that previous steps were completed |

### §3-2. Step Repetition and Replay

Executing the same step multiple times to accumulate benefits or exploit non-idempotent operations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Coupon double-apply** | Submitting the "apply coupon" request multiple times before the first completes, or alternating between two coupon codes to bypass "already applied" checks | Coupon validation is not atomic with order total update |
| **Referral self-loop** | Completing a referral flow and then re-submitting the referral with the same or different accounts to accumulate bonuses | Referral system checks "has this code been used?" but not "is this the same person?" |
| **Password reset token replay** | Using the same password reset token multiple times if the server doesn't invalidate it after first use | Token invalidation happens asynchronously or not at all |
| **Vote/rating inflation** | Submitting ratings or votes repeatedly; the server checks "has this session voted?" but session can be recreated | Rate limiting tied to session/cookie rather than account/IP |

### §3-3. Reverse Flow Exploitation

Going backwards in a process to modify data that was already validated.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-validation modification** | Completing validation on step 2, going back to step 1, modifying validated data, then proceeding to step 3 — the modified data isn't re-validated | Validation happens only at the step where data is entered |
| **Cart modification after pricing** | Price is calculated at cart review, but items can be added/modified between price calculation and payment submission | Pricing and checkout are not atomic operations |
| **Approval-then-edit** | A workflow item (document, request) is approved, then the submitter edits it after approval but before execution | Edit permission isn't revoked after approval, and execution uses current (edited) state |

---

## §4. Implicit Trust Boundaries — "This Value Came from Us"

The developer assumes certain values are server-controlled and cannot be modified by the client. In reality, any value in the HTTP request (headers, cookies, hidden fields, client-computed values) can be manipulated.

### §4-1. Client-Side Enforcement Trust

Security logic is implemented in client-side code and assumed to be enforced.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hidden field manipulation** | HTML hidden fields like `<input type="hidden" name="price" value="99.99">` are modified before submission | Price/role/permission stored in hidden fields without server-side re-validation |
| **Client-side role check bypass** | JavaScript hides admin UI elements with `if (user.role !== 'admin') { hide(adminPanel) }`; the API endpoints behind those UI elements have no server-side authorization | Frontend and backend authorization are assumed to be equivalent |
| **JavaScript validation bypass** | Client-side form validation (regex, length checks, required fields) is the only validation layer; disabling JavaScript or using a proxy bypasses all checks | No server-side validation mirrors client-side rules |
| **Disabled field submission** | HTML `disabled` attribute prevents form submission in the browser, but the field can be enabled via DevTools or sent directly via HTTP request | Server accepts and processes fields regardless of client-side `disabled` state |

### §4-2. Internal Header/Metadata Trust

The application trusts HTTP headers or internal metadata that are meant to be set by infrastructure (proxy, CDN, framework) but can be spoofed by external attackers.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Forwarded-For IP spoofing** | Application uses `X-Forwarded-For` header for IP-based access control or rate limiting; attacker sets this header to a whitelisted IP | No trusted proxy configuration to strip/override client-set headers |
| **X-Middleware-Subrequest bypass** | Next.js middleware uses `x-middleware-subrequest` header to detect internal subrequests and skip middleware execution; attacker spoofs this header to bypass all middleware-based auth (CVE-2025-29927) | Framework trusts an internal header without origin verification |
| **X-Original-URL / X-Rewrite-URL** | Reverse proxies use these headers to indicate the original URL; if the backend trusts them, an attacker can override the apparent request path to bypass path-based access controls | Backend checks the override header instead of the actual request URL |
| **Host header manipulation** | Application uses `Host` header for password reset links, redirect URLs, or virtual host routing; attacker modifies `Host` to inject malicious URLs | No allowlist for expected `Host` values; password reset poisoning |
| **Custom auth header injection** | Internal services expect headers like `X-User-ID` or `X-Authenticated-User` set by an API gateway; if the gateway doesn't strip these from external requests, attackers can impersonate any user | API gateway doesn't enforce header stripping for external traffic |

### §4-3. Client-Computed Value Trust

The server accepts computed values from the client that should be calculated server-side.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Client-side price calculation** | Cart total or item price is sent from the client in the checkout request; modifying it to `0.01` processes the order at attacker's price | Server doesn't recalculate price from item catalog |
| **Client-side discount application** | Discount percentage or amount is computed client-side and sent as a parameter; attacker can set arbitrary discount | No server-side discount recalculation |
| **Client-side hash/signature** | HMAC or hash is computed in JavaScript with a key visible in source; attacker regenerates valid signatures for modified data | Signing key exposed in client-side code |
| **Client-side expiry check** | Token or session expiry is checked only in client-side JavaScript; server accepts expired tokens because it delegates expiry checking to the client | JWT `exp` claim checked client-side but not server-side |

---

## §5. Mass Assignment and Binding Abuse — "We Control the Schema"

The developer assumes that only expected fields will be submitted. Framework auto-binding mechanisms (Rails `params`, Spring `@ModelAttribute`, Django `ModelForm`) automatically map request parameters to model properties, allowing attackers to set unintended fields.

### §5-1. Direct Property Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Role/privilege escalation** | Sending `{"role": "admin"}` or `{"is_admin": true}` alongside a normal profile update; the ORM binds it to the user model | No allowlist/blocklist for bindable fields |
| **Ownership transfer** | Sending `{"owner_id": attacker_id}` to transfer ownership of a resource during an update operation | Foreign key fields are bindable without authorization check |
| **Internal state manipulation** | Setting `{"email_verified": true}`, `{"account_status": "active"}`, or `{"balance": 99999}` through parameter injection | Internal state flags are part of the same model that accepts user input |
| **Relationship injection** | Sending nested parameters like `{"user": {"organization_id": 1}}` to associate the user with a different organization | Nested/associated model bindings are not restricted |

### §5-2. Merge/Spread Operator Abuse

Modern JavaScript patterns using object spread (`{...defaults, ...userInput}`) or `Object.assign()` allow user input to override any default property.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default override** | `Object.assign(config, userInput)` allows the user to override any configuration property including security-sensitive ones | Spread/assign order places user input last |
| **Prototype pollution** | Sending `{"__proto__": {"isAdmin": true}}` through a recursive merge function pollutes the Object prototype, affecting all objects in the application | Merge function doesn't skip `__proto__`, `constructor`, `prototype` keys |
| **Deep merge traversal** | Nested merge operations like `deepMerge(defaults, userInput)` allow overriding deeply nested configuration properties | No depth limit or key blocklist on merge operations |

---

## §6. Parser and Semantic Differentials — "We All Read It the Same Way"

Different components in the request pipeline (WAF, proxy, framework, application, database) parse the same input differently, creating gaps where one component validates but another interprets differently.

### §6-1. Parameter Parsing Differentials

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTTP Parameter Pollution (HPP)** | Sending `?user=admin&user=guest`; PHP takes the last value, ASP.NET takes the first, Java concatenates them — validation and execution may use different values | Multi-tier architecture with different parameter-handling behaviors |
| **Parameter format confusion** | Sending data as JSON body when the WAF expects form-encoded, or vice versa; the WAF can't parse it but the application can | WAF and application support different Content-Types |
| **Duplicate key in JSON** | Sending `{"role": "user", "role": "admin"}`; JSON parsers handle duplicate keys differently — the first wins in some, the last in others | Validation parser and execution parser disagree on which key wins |
| **Comment injection in JSON** | Some JSON parsers accept `/* comments */` or `// comments` (non-standard); injecting comments can break field matching in validation while the permissive backend parser processes the data normally | Strict validator vs. permissive parser |
| **Bracket notation variance** | `param[0]` vs `param[]` vs `param.0` are handled differently across frameworks; mixing notations can create arrays, objects, or strings depending on the parser | Framework-specific parameter parsing quirks |

### §6-2. Path and URL Differentials

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Path traversal normalization** | `/admin/../public/../admin/secret` — the proxy normalizes to `/public` and allows it, the backend normalizes to `/admin/secret` | Proxy and backend use different path normalization algorithms |
| **Encoded path confusion** | `/admin` is blocked but `/%61dmin` (URL-encoded `a`) is allowed by the WAF but decoded by the backend | WAF validates encoded form, backend normalizes before routing |
| **Trailing dot/slash/semicolon** | `/admin/` vs `/admin` vs `/admin;` vs `/admin.` routed differently by proxy and backend; access controls apply to one form but not others | Apache mod_rewrite, Tomcat path parameter handling, IIS trailing dot |
| **Fragment and query confusion** | Request contains `#fragment` that's ignored by the server but affects client-side routing, or `?` characters that create parser confusion between path and query components (CVE-2024-38474) | Multi-layer request processing with inconsistent URL parsing |

### §6-3. Semantic Ambiguity Exploitation

Exploiting the gap between *intended meaning* and *parsed meaning* of the same input.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Confusion Attacks (Apache)** | Exploiting how Apache HTTP Server internally maps URLs through multiple modules (mod_rewrite, mod_alias, mod_proxy), creating semantic ambiguity in what a URL means at each processing stage | Complex Apache configuration with multiple URL-mapping modules |
| **Content-Type vs actual content** | Sending a JSON payload with `Content-Type: application/xml`; the WAF parses as XML (finds nothing suspicious), the backend ignores Content-Type and detects JSON | WAF relies on Content-Type for parser selection |
| **Method override confusion** | Using `X-HTTP-Method-Override: DELETE` on a `POST` request; the proxy sees `POST` (allowed), the application sees `DELETE` (restricted) | Proxy/WAF and application disagree on the effective HTTP method |
| **Charset/encoding mismatch** | Declaring `charset=utf-7` or `charset=shift_jis` in Content-Type while sending UTF-8; different layers decode differently, creating injection opportunities | Multi-layer processing with charset-dependent decoding |

---

## §7. Numeric and Boundary Logic — "Values Will Be Reasonable"

The developer assumes numeric inputs will be within reasonable ranges and positive. Extreme, negative, or specially crafted numeric values trigger integer overflow, underflow, or boundary-condition bugs.

### §7-1. Negative Value Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Negative quantity for credit** | Setting item quantity to `-1` in a cart; total becomes negative, and checkout issues a credit or refund | No unsigned/positive validation on quantity fields |
| **Negative transfer amount** | Sending a money transfer with amount `-100` reverses the transfer direction, moving money from recipient to sender | Transfer logic uses `sender.balance -= amount; recipient.balance += amount` without sign check |
| **Negative discount inversion** | Setting a discount value to `-50%` (negative discount) increases the price, which in some systems triggers a different code path that may skip payment validation | Discount processing doesn't validate sign |

### §7-2. Integer Overflow and Wraparound

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Quantity overflow to negative** | Setting quantity to `9223372036854775808` (2^63) overflows a signed 64-bit integer to `-9223372036854775808`, resulting in a negative total | Backend uses signed integer for quantity without bounds checking |
| **Price multiplication overflow** | `price × quantity` overflows the integer type, wrapping around to a small or negative number | No bounds check before arithmetic operation |
| **ID/offset overflow** | Setting pagination `offset` to `MAX_INT` causes the database query to return unexpected results or error out in exploitable ways | Direct use of user-supplied integers in database queries |

### §7-3. Floating Point and Precision Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rounding exploitation** | Transferring `$0.001` thousands of times; each individual transfer rounds down to `$0.00` on the sender's side but accumulates on the recipient's side (salami attack) | Rounding applied asymmetrically between debit and credit |
| **Floating point comparison failure** | `0.1 + 0.2 !== 0.3` in IEEE 754; financial validation that checks `if (paid === total)` fails for legitimate transactions or passes for manipulated ones | Floating-point comparison for monetary values |
| **Scientific notation injection** | Sending `"amount": "1e-10"` which parses to `0.0000000001` and passes a `> 0` check but represents essentially zero payment | String-to-number conversion accepts scientific notation |

---

## §8. Race Conditions and Temporal Logic — "Operations Are Atomic"

The developer assumes that check-then-act sequences execute atomically. Concurrent requests can exploit the gap between check and act to violate business constraints.

### §8-1. Limit Overrun (TOCTOU)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Coupon usage limit bypass** | Coupon has `max_uses: 1`; sending 20 simultaneous requests all pass the "is coupon used?" check before any one marks it as used | Check-then-update is not wrapped in a transaction with row-level locking |
| **Balance double-spend** | Account has $100; two simultaneous $100 withdrawal requests both read balance as $100, both pass validation, both execute, resulting in -$100 | Balance check and deduction are separate, non-atomic operations |
| **Rate limit bypass** | Rate limiter allows 5 requests/minute; sending 50 requests simultaneously via single-packet attack (HTTP/2) all arrive before the counter increments | Rate counter uses non-atomic increment, or timing window exists |
| **Inventory oversell** | Product has stock=1; concurrent purchase requests all read stock=1, all validate, all decrement, resulting in negative stock | Stock check and decrement are not atomic |

### §8-2. State Transition Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Follow-unfollow race** | Rapidly toggling follow/unfollow on a social platform; the notification or follower count increments on follow but doesn't always decrement on unfollow due to race conditions | Counter operations are not serialized |
| **Account deletion race** | Deleting an account while simultaneously performing actions; the actions execute with the account in a partially-deleted state, potentially leaving orphaned data or bypassing cleanup | Deletion and regular operations share no transaction boundary |
| **Concurrent session manipulation** | Two concurrent requests modify different fields of the same session; last-write-wins causes one modification to be lost, potentially reverting a security-relevant change | Session storage uses non-atomic read-modify-write |

### §8-3. Temporal Ordering Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gift card race** | Redeeming the same gift card simultaneously from multiple sessions; all sessions verify the card is valid before any marks it as redeemed (CVE-2024-58248, nopCommerce) | Gift card redemption is not idempotent or transactionally locked |
| **Promo code race** | Same as coupon bypass but specifically targeting limited promotional offers; the single-packet attack technique sends all requests in one TCP packet for near-zero timing variance | HTTP/2 multiplexing enables single-packet attack |
| **OTP brute-force via batching** | GraphQL batching allows sending thousands of OTP guesses in a single HTTP request, bypassing per-request rate limiting | Rate limiter counts HTTP requests, not GraphQL operations |

---

## §9. Cryptographic and Token Logic — "The Token Guarantees Identity"

The developer assumes tokens, signatures, and cryptographic operations provide the guarantees they're designed for. Logic flaws in *how* these are used (not in the crypto itself) create bypasses.

### §9-1. Algorithm Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JWT `alg: none`** | Setting the JWT algorithm to `"none"`, `"None"`, `"nOnE"` removes signature verification entirely; the token is accepted as valid without any signature | Server honors the `alg` field from the token header instead of enforcing a fixed algorithm |
| **JWT RS256→HS256 confusion** | Changing the algorithm from RS256 (asymmetric) to HS256 (symmetric) and signing with the public key (which is... public); the server uses the public key as HMAC secret to verify | Server uses `alg` from token to select verification algorithm |
| **SAML signature wrapping** | Moving the legitimate signed assertion to a non-validated location and injecting a forged assertion in the expected location; the server verifies the signature on the wrong assertion | SAML processor validates signature and extracts identity from different XML nodes |
| **XML canonicalization confusion** | Variations in XML canonicalization (C14N) cause the same XML document to produce different canonical forms, allowing forged signatures that verify against attacker-controlled content | SAML library uses inconsistent canonicalization between signing and verification |

### §9-2. Token Lifecycle Flaws

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Password reset token non-invalidation** | Token remains valid after use; attacker who intercepts it can reuse it indefinitely | Server doesn't mark token as consumed after password change |
| **Token leakage via Referer** | Password reset URL containing the token is sent; when the user clicks a link on the reset page, the token is leaked in the `Referer` header to the linked site | Reset page contains external links (tracking, analytics, social) |
| **Predictable token generation** | Reset tokens generated from `MD5(timestamp)` or `MD5(email + timestamp)` can be brute-forced if the attacker knows approximate generation time | Insufficient entropy in token generation |
| **Token scope confusion** | An email verification token is accepted by the password reset endpoint, or vice versa; tokens aren't scoped to their intended operation | Tokens lack a type/purpose field in their payload |
| **Session fixation on SSO** | Attacker obtains a session ID before authentication, feeds it to the victim via the SSO login URL; after the victim authenticates, the attacker's session is now authenticated | Session ID is not regenerated after SSO callback |

### §9-3. Verification Logic Flaws

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Signature verification skip on empty signature** | Some libraries return "success" when verifying an empty signature against any payload, because the empty-string case isn't handled | Library/application doesn't check for signature presence before verification |
| **Partial signature verification** | Only the first N bytes of a signature are checked, or the signature covers only part of the payload; attacker modifies uncovered portions | Custom signature implementation with incomplete coverage |
| **Certificate chain bypass** | Self-signed certificate is accepted because the verification only checks format, not trust chain; or a valid certificate for a different domain is accepted | Certificate validation checks structure but not issuer or subject |

---

## §10. Access Control Assumption Flaws — "The UI Is the Security Boundary"

The developer implements access control at the UI layer (hiding buttons, not showing menu items) but not at the API/endpoint layer. Any user who discovers or guesses the endpoint can access it.

### §10-1. Horizontal Access Control Bypass (IDOR)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sequential ID enumeration** | Changing `GET /api/users/123/profile` to `GET /api/users/124/profile` to access another user's data | No authorization check beyond authentication |
| **UUID/slug guessing** | Even with non-sequential identifiers, endpoints like `/api/invoices/{uuid}` may not verify the requesting user owns that invoice | Authorization relies on obscurity of identifiers |
| **Cross-method IDOR** | `GET /api/orders/123` is properly protected, but `DELETE /api/orders/123` or `PUT /api/orders/123` lacks the same check | Authorization applied per-method inconsistently |
| **Nested resource IDOR** | `/api/organizations/1/users/5` verifies org membership but not that user 5 belongs to org 1; attacker accesses user 5 across org boundaries | Only top-level resource ownership is checked |
| **Response body IDOR** | The API endpoint itself is protected, but the response contains references (URLs, IDs) to other users' resources that can be directly accessed | Response data leaks valid resource identifiers |

### §10-2. Vertical Access Control Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct admin endpoint access** | `/admin/delete-user` is hidden from the UI for non-admins but has no server-side role check | Security-by-obscurity; endpoint discovery via JavaScript source, documentation, or brute-force |
| **API version bypass** | `/api/v2/admin/users` has proper auth; `/api/v1/admin/users` (deprecated but still running) doesn't | Old API versions not decommissioned or retrofitted with auth |
| **Feature flag bypass** | Feature flags control UI visibility but not API access; disabled features' endpoints remain accessible | Feature flags implemented client-side only |
| **Method-based bypass** | `GET /admin` returns 403, but `POST /admin`, `HEAD /admin`, or non-standard methods like `FOOBAR /admin` bypass the method-specific ACL rule | ACL rules only cover specific HTTP methods |
| **Path normalization bypass** | `/admin` is blocked but `/Admin`, `/ADMIN`, `/admin/`, `/admin/.`, `/admin..;/` bypass the exact-match ACL rule | Case-sensitive or strict path matching in ACL, case-insensitive routing in application |

---

## §11. SSO and OAuth Logic Flaws — "The Protocol Handles Security"

Developers trust that SSO/OAuth protocols inherently provide security guarantees. Logic flaws in the *integration* — not the protocol specification — create account takeover vectors.

### §11-1. Account Linking Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Email-based auto-linking** | User registers with `victim@example.com` via email, then attacker creates an OAuth identity with the same email; the application auto-links them, giving attacker access to victim's account | OAuth email is trusted without verification; auto-linking by email match |
| **Pre-registration hijack** | Attacker pre-registers an account with victim's email (unverified); when victim later does SSO login with that email, the SSO identity is linked to attacker's pre-existing account | Account creation doesn't require email verification before SSO linking |
| **OAuth state parameter CSRF** | Attacker initiates OAuth flow, captures the callback URL with authorization code, and tricks victim into visiting it; victim's session is now linked to attacker's OAuth identity | Missing or improperly validated `state` parameter |

### §11-2. Redirect and Callback Flaws

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Open redirect to token theft** | OAuth `redirect_uri` validation allows subpath variations like `https://app.com/callback/../attacker`; authorization code or token is sent to attacker-controlled path | Insufficient redirect_uri validation (prefix match instead of exact match) |
| **Token in URL fragment leakage** | Implicit flow returns token in URL fragment (`#access_token=...`); if the page loads resources from third-party domains, the Referer header may leak it | Implicit grant flow with external resource loading |
| **Cookie tossing on OAuth callback** | Attacker sets a cookie on a parent domain that overrides the session cookie during the OAuth callback, hijacking the flow | Shared parent domain between attacker-controlled subdomain and application |

---

## §12. Default and Fallback Abuse — "Reasonable Defaults Are Safe"

The developer sets default values or fallback behaviors that seem reasonable but create security-relevant behaviors when exploited.

### §12-1. Insecure Default Values

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default admin credentials** | Application ships with `admin:admin` or similar default credentials; deployment documentation mentions changing them but doesn't enforce it | No forced password change on first login |
| **Default open permissions** | New resources are created with `public` visibility by default; users must manually set them to `private` | Security-relevant defaults are permissive rather than restrictive |
| **Debug mode in production** | Debug/development mode enabled by default; verbose error messages, stack traces, or debug endpoints exposed in production | Framework defaults to debug mode; deployment doesn't explicitly set production mode |
| **Default CORS wildcard** | CORS policy defaults to `Access-Control-Allow-Origin: *` or reflects the `Origin` header; cross-origin requests can steal user data | Framework or middleware defaults to permissive CORS |

### §12-2. Fallback Path Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Authentication fallback** | Primary authentication fails (LDAP timeout, OAuth error); system falls back to a weaker local authentication mechanism that has a default password or no password | Fallback is designed for availability, not security |
| **Error-path bypass** | Validation throws an exception; the catch block proceeds with the default (unvalidated) value rather than rejecting the request | Exception handling defaults to "continue" rather than "deny" |
| **Missing config fallback** | Configuration for auth/encryption is missing; application falls back to `none`/`disabled` instead of failing closed | Application prefers availability over security in configuration errors |
| **Downgrade attack** | Client advertises it doesn't support secure protocol version/feature; server falls back to an insecure version to maintain compatibility | No minimum security floor enforced; graceful degradation enables downgrade |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Authentication Bypass** | Login, SSO, MFA flows | §1 + §3 + §9 + §11 |
| **Privilege Escalation** | Multi-role applications | §4 + §5 + §10 |
| **Financial Exploitation** | E-commerce, fintech | §7 + §8 + §4-3 |
| **Data Access Violation** | Multi-tenant APIs | §10-1 + §6 + §2 |
| **Rate Limit Bypass** | Anti-automation defenses | §1-1 + §8 + §6-1 |
| **Account Takeover** | Password reset, SSO linking | §9-2 + §11-1 + §3-1 |
| **Cache/Proxy Poisoning** | CDN, reverse proxy architectures | §6-2 + §6-3 + §4-2 |
| **State Corruption** | Workflows, multi-step processes | §3 + §8-2 + §5 |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §4-2 (Internal header trust) | CVE-2025-29927 (Next.js) | Critical auth bypass; middleware entirely skipped via `x-middleware-subrequest` header spoofing. CVSS 9.1 |
| §9-1 (JWT alg:none) | CVE-2024-48916 (Ceph RadosGW) | Authentication bypass via `alg: none` in JWT; unauthorized access to OIDC-protected resources |
| §9-1 (SAML signature wrapping) | CVE-2025-47949 (samlify) | Full authentication bypass; arbitrary user impersonation via forged SAML responses. CVSS 9.8 |
| §9-1 (SAML xml-crypto) | SAMLStorm (xml-crypto, March 2025) | Zero-day in Node.js ecosystem; forged SAML auth responses enabling admin account takeover |
| §9-1 (SAML bypass) | CVE-2024-45409 (ruby-saml) | GitLab SAML auth bypass; arbitrary user login. CVSS 10.0 |
| §9-1 (SAML bypass) | CVE-2025-59718/59719 (Fortinet FortiGate) | Active exploitation in wild; unauthenticated SSO bypass. CVSS 9.8 |
| §6-3 (Semantic ambiguity) | CVE-2024-38474/75/76/77 (Apache httpd) | Confusion Attacks: 9 vulnerabilities via semantic ambiguity in URL processing across modules |
| §8-1 (Race condition) | CVE-2024-58248 (nopCommerce) | Gift card double-redemption via race condition in order placement |
| §9-2 (Token leakage) | CVE-2025-58434 (FlowiseAI) | Critical account takeover; password reset token returned in API response. CVSS 9.8 |
| §7-2 (Integer overflow) | Glovo HackerOne #1562515 | Integer overflow in quantity field wrapping to negative, enabling price manipulation |
| §4-2 (Host header) | CVE-2025-0108 (PAN-OS) | Authentication bypass in management web interface via crafted requests |
| §9-1 (JWT algorithm confusion) | CVE-2024-54150 (cjwt library) | Algorithm confusion allowing token forgery |
| §8-3 (OTP batching) | GraphQL batching + OTP brute-force | 2FA bypass by sending all OTP combinations in a single batched GraphQL request |
| §3-1 (Step skipping) | CVE-2024-4358 (Telerik Report Server) | Auth bypass via registration endpoint that should have been gated behind existing auth |
| §2-3 (Unicode normalization) | CVE-2024-43093 (Android) | Privilege escalation via Unicode normalization bypass in file path filter |
| §2-3 (Unicode normalization) | CVE-2025-52488 (DNN/DotNetNuke) | NTLM credential leak via Unicode normalization creating UNC paths |
| §11-2 (Cookie tossing) | Top 10 Web Hacking 2024 finalist | OAuth flow hijacking via Cookie Tossing technique |
| §6-2 + §6-3 (Path + cache) | ChatGPT account takeover | Web Cache Deception via inconsistent decoding enabling path traversal. Top 10 2024 |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Pro** (Scanner + Manual) | All categories; §6, §8 especially strong | Automated scanning with manual testing via Repeater/Intruder; single-packet attack for race conditions |
| **Burp Turbo Intruder** (Extension) | §8 (Race conditions) | Python-scripted concurrent request sending; single-packet HTTP/2 attack |
| **Param Miner** (Burp Extension) | §4-2, §6-1 (Hidden headers/params) | Automated discovery of hidden parameters and headers via brute-force and heuristics |
| **Autorize** (Burp Extension) | §10 (Access control) | Replays requests with different authorization tokens to detect IDOR and privilege escalation |
| **JWT_Tool** (CLI) | §9-1 (JWT attacks) | Automated testing of JWT `alg:none`, key confusion, claim tampering |
| **SAMLRaider** (Burp Extension) | §9-1 (SAML attacks) | SAML signature wrapping, assertion modification, XXE testing |
| **NoSQLMap** (CLI) | §2-2 (NoSQL injection via type confusion) | Automated NoSQL injection testing including operator injection |
| **GraphQL Voyager / InQL** (Burp Extension) | §8-3, §10 (GraphQL) | Introspection enumeration, batching abuse, authorization testing |
| **Nuclei** (CLI) | Multiple categories | Template-based vulnerability scanning; community templates for CVE-2025-29927, SAML bypasses, etc. |
| **OWASP ZAP** (Scanner) | §1, §4, §10 (General logic) | Active/passive scanning with logic flaw detection scripts |
| **Race The Web** (CLI) | §8 (Race conditions) | Concurrent request testing for TOCTOU vulnerabilities |

---

## Summary: Core Principles

### The Fundamental Property

Web application logic bugs exist because **software encodes assumptions as code, and HTTP makes those assumptions testable**. Every conditional check, every type expectation, every state transition, every trust boundary is an implicit contract between the developer's mental model and reality. HTTP — as a stateless, text-based, client-controlled protocol — gives attackers the ability to violate any of these contracts trivially. You can omit fields, change types, reorder steps, replay requests, and spoof headers with nothing more than a proxy tool.

### Why Incremental Fixes Fail

Logic bugs resist automated detection and pattern-based fixes because they are **context-dependent**: the same code pattern (e.g., `if (field) { validate(field) }`) is perfectly safe in one context and critically vulnerable in another. Unlike injection vulnerabilities where the fix is universal (parameterized queries, output encoding), logic bug fixes require understanding the *business intent* behind each check. This is why business logic flaws are the fastest-growing vulnerability category — as injection bugs decrease through framework-level protections, logic bugs remain stubbornly human.

### The Structural Solution

The structural defense against logic bugs is **defensive programming at trust boundaries**:
1. **Validate presence, not just content** — every security-critical field must be required, not optional.
2. **Enforce types strictly** — use schema validation (JSON Schema, protobuf, typed languages) to reject unexpected types before business logic executes.
3. **Make state machines explicit** — model workflows as finite state machines with server-side enforcement of transitions.
4. **Compute server-side, verify server-side** — never trust client-computed values for security decisions.
5. **Use atomic operations** — wrap check-then-act sequences in database transactions with appropriate isolation levels.
6. **Allowlist, don't blocklist** — for mass assignment, parameter binding, and CORS, explicitly define what's permitted.
7. **Fail closed** — missing config, failed validation, and exception paths should deny access, not grant it.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- PortSwigger Web Security Academy — Business Logic Vulnerabilities: https://portswigger.net/web-security/logic-flaws
- PortSwigger Research — Top 10 Web Hacking Techniques 2024/2025: https://portswigger.net/research/top-10-web-hacking-techniques
- Orange Tsai — Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server (Black Hat USA 2024): https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
- OWASP Business Logic Abuse Top 10 Project: https://owasp.org/www-project-top-10-for-business-logic-abuse/
- OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- Bishop Fox — JSON Interoperability Vulnerabilities: https://bishopfox.com/blog/json-interoperability-vulnerabilities
- Sonar — Security Implications of URL Parsing Differentials: https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/
- PayloadsAllTheThings — Type Juggling: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md
- Datadog Security Labs — CVE-2025-29927 Next.js Middleware Bypass: https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/
- WorkOS — SAMLStorm: Critical Authentication Bypass in xml-crypto: https://workos.com/blog/samlstorm
- PortSwigger Research — Race Conditions: https://portswigger.net/web-security/race-conditions
- CWE-190: Integer Overflow or Wraparound: https://cwe.mitre.org/data/definitions/190.html
- Iterasec — Parser Differential Vulnerabilities: https://iterasec.com/blog/understanding-parser-differential-vulnerabilities/
- HackerOne — Business Logic Vulnerability Reports (various)
- OWASP Web Security Testing Guide — Parameter Pollution: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
