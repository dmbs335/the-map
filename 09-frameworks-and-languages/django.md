# Django Framework Vulnerability Mutation Taxonomy

---

## Classification Structure

This taxonomy organizes Django framework vulnerabilities by **structural mutation target** — the specific architectural component being exploited. Django's layered architecture (ORM → Template Engine → URL Router → Middleware → Auth System → File Handling → Serialization → Configuration) creates distinct attack surfaces at each layer, and vulnerabilities cluster predictably around these boundaries.

**Axis 1 (Primary — Mutation Target):** The Django architectural component whose input processing or trust boundary is violated. This axis structures the main body of the document into 9 top-level categories (§1–§9).

**Axis 2 (Cross-Cutting — Discrepancy Type):** The nature of the security failure that enables exploitation. These discrepancy types recur across multiple architectural components:

| Discrepancy Type | Description | Recurring In |
|-----------------|-------------|-------------|
| **Insufficient Sanitization** | User input reaches SQL/HTML/headers without proper escaping | §1, §2, §6 |
| **Algorithmic Complexity** | Crafted input causes exponential/super-linear processing time | §2, §6, §9 |
| **Validation Bypass** | Input passes validation but retains malicious properties | §3, §5, §9 |
| **Configuration-Dependent Exposure** | Security depends on correct settings easily misconfigured | §4, §7, §8 |
| **Trust Boundary Violation** | Internal API trusts external input without re-validation | §1, §4, §5 |
| **Parser Differential** | Different components interpret the same input differently | §3, §6 |
| **Privilege Boundary Violation** | Access control checks can be circumvented | §4, §8 |

**Axis 3 (Mapping — Attack Scenario):** The weaponized impact — RCE, data exfiltration, authentication bypass, DoS, client-side attack, or SSRF. Mapped in §10.

### Fundamental Root Cause

Django's security model is built on **layered defense through parameterization and escaping** — the ORM parameterizes queries, the template engine auto-escapes output, middleware enforces headers. Vulnerabilities arise when:

1. **Escape hatches exist** — `raw()`, `extra()`, `|safe`, `@csrf_exempt` bypass the default protections
2. **Dictionary expansion (`**kwargs`) bridges trust boundaries** — user-controlled dictionaries expand into internal APIs that assume trusted input
3. **Utility functions accept unbounded input** — validators, text processors, and HTML utilities lack upper-bound enforcement
4. **Backend-specific SQL generation diverges** — Oracle, PostgreSQL, MySQL each generate different SQL from the same ORM call

---

## §1. ORM & Query Construction (SQL Injection Surface)

SQL injection in Django occurs not through the classic `' OR 1=1--` against parameterized queries, but through **ORM API abuse** — exploiting functions, lookups, and query construction methods that assemble SQL fragments without full parameterization. This is Django's most critical and most frequently recurring vulnerability class, with 17+ CVEs spanning 2014–2026.

### §1-1. Dictionary Expansion into Query Methods

The most severe modern Django SQL injection vector. When applications pass user-controlled dictionaries directly into ORM methods via Python's `**kwargs` expansion, internal query-control parameters become attacker-accessible.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`_connector` injection** | `filter(**request.GET.dict())` allows injecting `_connector=OR` to alter query logic from AND to OR, enabling authentication bypass (e.g., `_connector=OR&is_superuser=True`) | Application uses `**request.GET.dict()` or `**request.POST.dict()` in filter()/exclude()/get() |
| **`_negated` injection** | Injecting `_negated=True` inverts the entire query condition, turning exclusion into inclusion | Same as above; Q() objects also vulnerable |
| **Column alias injection via annotate()** | `annotate(**user_dict)` allows crafted dictionary keys to inject SQL fragments as column aliases | Application expands user input into annotate() or alias() kwargs |
| **FilteredRelation alias injection** | FilteredRelation combined with dictionary expansion in annotate()/alias() allows SQL injection through column alias generation | PostgreSQL and other backends; dictionary expansion pattern |

**Example — CVE-2025-64459 (CVSS 9.1):**
```
GET /api/items/?_connector=OR&is_superuser=True
→ QuerySet.filter(_connector='OR', is_superuser=True)
→ WHERE (is_superuser = True)  -- bypasses intended filter
```

**Example — CVE-2025-57833 / CVE-2025-13372 (FilteredRelation):**
```python
# Attacker controls dict keys passed to annotate()
QuerySet.annotate(**{malicious_alias: FilteredRelation(...)})
# Malicious alias injects SQL fragment into column definition
```

### §1-2. Database Function Argument Injection

Django's date/time database functions accept string arguments that are interpolated into SQL without parameterization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trunc(kind) injection** | The `kind` parameter of `Trunc()` is interpolated directly into SQL; crafted values inject arbitrary SQL | Application passes user input as `kind` argument |
| **Extract(lookup_name) injection** | The `lookup_name` parameter of `Extract()` is similarly unparameterized | Application passes user input as `lookup_name` |

**Example — CVE-2022-34265:**
```
GET /report/?kind=year', start_datetime)) OR 1=1; SELECT PG_SLEEP(5)--
→ SQL: CAST(DATE_TRUNC('year', start_datetime)) OR 1=1; SELECT PG_SLEEP(5)-- ...
```

### §1-3. Backend-Specific Lookup Injection

Certain ORM lookups generate backend-specific SQL that lacks parameterization on specific database engines.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HasKey on Oracle** | `django.db.models.fields.json.HasKey` lookup generates unparameterized SQL on Oracle when used directly (not via `__has_key` ORM syntax) | Oracle backend; direct HasKey usage with untrusted `lhs` |
| **GIS raster band index** | Raster lookups on PostGIS fields interpolate the band index into SQL without parameterization | PostGIS backend; untrusted band index value |
| **GIS tolerance on Oracle** | The `tolerance` parameter in GIS functions for Oracle is interpolated directly | Oracle backend; untrusted tolerance value |

**Example — CVE-2024-53908:**
```python
# Direct HasKey usage on Oracle — vulnerable
HasKey(lhs=user_input, rhs='key')
# ORM syntax — NOT vulnerable
Model.objects.filter(jsonfield__has_key='key')
```

### §1-4. Query Method Argument Injection

Several QuerySet methods accept arguments that are partially interpolated into SQL.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **order_by() injection** | Unsanitized input in `order_by()` can inject SQL fragments | User controls ordering field names |
| **values()/values_list() injection** | Field names in `values()` and `values_list()` can inject SQL on certain backends | User controls field selection |
| **aggregate()/extra() injection** | Keyword arguments to `aggregate()` and `extra()` allow SQL fragment injection, especially on MySQL/MariaDB | Dictionary expansion into these methods |
| **explain() on PostgreSQL** | Options passed to `QuerySet.explain()` are interpolated into SQL | User controls explain options |
| **StringAgg(delimiter)** | The delimiter argument to PostgreSQL's `StringAgg` aggregation is interpolated without escaping | User controls delimiter value |

### §1-5. Legacy and Deprecated Unsafe APIs

Django retains several APIs that bypass parameterization entirely.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **raw() queries** | `Model.objects.raw(sql)` executes raw SQL; string formatting of user input creates classic SQLi | Developer uses string formatting instead of parameterized raw() |
| **extra() clauses** | `QuerySet.extra(where=[...], select={...})` inserts SQL fragments directly | Any user input in extra() arguments; API deprecated but still functional |
| **RawSQL expressions** | `RawSQL(sql, params)` allows raw SQL in annotations/aggregations | Insufficient parameterization in RawSQL usage |
| **cursor.execute()** | Direct database cursor usage bypasses ORM protections entirely | String formatting of user input in cursor queries |

### §1-6. JSON/HStore Field Lookup Injection

JSON and HStore field lookups have historically had insufficient parameterization for key/index access patterns.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Key lookup injection** | Key and index lookups on `JSONField` and `HStoreField` were historically vulnerable to SQL injection | Untrusted data in lookup keys; fixed in Django 2.2.4+ |
| **Deep key path injection** | Nested key access patterns (e.g., `data__key1__key2`) with untrusted segments | Attacker controls nested path segments |

---

## §2. Template Engine & Rendering

Django's template engine is sandboxed by design — it does not allow arbitrary Python execution in templates. However, specific template tags, filters, and rendering contexts create attack vectors for XSS, information disclosure, and denial of service.

### §2-1. Cross-Site Scripting via Template Context

Django auto-escapes template variables by default, but several mechanisms bypass this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`|safe` filter misuse** | Marking user-controlled content as `|safe` disables auto-escaping | Developer marks untrusted input as safe |
| **`{% autoescape off %}` blocks** | Disabling auto-escaping for entire template blocks | Untrusted content rendered within autoescape-off blocks |
| **`mark_safe()` in Python code** | Calling `mark_safe()` on user input in views/template tags | Developer wraps untrusted strings |
| **Admin widget XSS** | Admin widgets like `ForeignKeyRawIdWidget` and `AdminURLFieldWidget` rendered user-provided URLs without escaping | Admin interface with user-controllable URL fields |
| **`{% debug %}` tag XSS** | The debug template tag reflected database content without escaping, enabling stored XSS via carefully crafted model data | DEBUG mode or debug tag used in production |
| **Uploaded filename XSS** | Filenames of uploaded files displayed without sanitization | Admin or custom views rendering upload names |

### §2-2. Server-Side Template Injection (SSTI)

While Django's template language is intentionally restricted, SSTI becomes possible when user input is used to construct template strings dynamically.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dynamic template construction** | Using `Template(user_input)` or `render_to_string()` with user-controlled template content | Application builds templates from user input |
| **Template tag loading** | `{% load %}` can access custom template tag libraries that may have side effects (e.g., `{% load log %}` to access admin logs) | SSTI context where load tag is available |
| **Template variable traversal** | Django template variable resolution follows attribute chains, allowing access to object properties not intended to be exposed | Object attributes not properly restricted |

**Limitation:** Django SSTI is less severe than Jinja2 SSTI because Django templates cannot call arbitrary functions. The primary impacts are information disclosure and limited data access rather than RCE.

### §2-3. Template Filter Denial of Service

Several template filters and utility functions exhibit super-linear or exponential time complexity on crafted input.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`strip_tags()` / `striptags` filter** | Nested incomplete HTML entities cause exponential processing time | User-controlled input passed to strip_tags(); recurring CVE pattern (2015, 2019, 2024, 2025) |
| **`Truncator.words()` / `truncatewords_html`** | ReDoS via crafted HTML content | User-controlled content with truncation |
| **`urlize()` / `urlizetrunc` filter** | Super-linear processing on crafted URL-like strings; recurring vulnerability (2018, 2024 ×4) | User content auto-linked via urlize |
| **`floatformat` filter** | Memory exhaustion via very large numbers passed to `floatformat()` | User-controlled numeric strings |
| **`intcomma` filter** | DoS via crafted numeric input | User-controlled numbers formatted with intcomma |

### §2-4. Information Disclosure via Template Filters

Template filters designed for formatting can inadvertently expose internal data.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`date` filter settings leak** | The `date` template filter could leak settings by accepting settings-like format strings | User controls date format string |
| **`dictsort` filter traversal** | The `dictsort` filter could be used to access arbitrary model attributes by controlling the sort key | User controls sort key argument |

---

## §3. URL Routing, Validation & Redirect

Django's URL dispatcher, URL validators, and redirect utilities form a critical trust boundary between external requests and internal view dispatch.

### §3-1. Open Redirect

Django's redirect utilities and middleware contain vectors for redirecting users to attacker-controlled domains.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Redirect URL scheme bypass** | Redirect URLs with schemes other than http/https (e.g., `javascript:`) bypass validation | Insufficient scheme validation in redirect targets |
| **Numeric URL redirect** | Numeric-like URLs (e.g., `10.0.0.1`) misinterpreted as redirect targets | `is_safe_url()` validation bypass |
| **Basic auth in URL** | URLs with embedded credentials (`http://evil.com@legitimate.com`) bypass host validation | URL parsing inconsistency |
| **CommonMiddleware APPEND_SLASH redirect** | When `APPEND_SLASH=True`, the middleware appends a slash and redirects, potentially creating open redirects on crafted paths | APPEND_SLASH enabled (default) |
| **`static.serve()` redirect** | Django's static file serving view contained open redirect via crafted path | Using `django.views.static.serve()` in production |

### §3-2. Host Header Injection

Manipulation of the HTTP `Host` header to poison absolute URL generation, cache behavior, and redirect targets.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`get_host()` bypass via direct META access** | Accessing `request.META['HTTP_HOST']` directly bypasses Django's `get_host()` host validation | Developer reads Host header from META dict |
| **`X-Forwarded-Host` injection** | When `USE_X_FORWARDED_HOST=True`, the X-Forwarded-Host header overrides Host without additional validation | USE_X_FORWARDED_HOST enabled; no trusted proxy restriction |
| **Host header cache poisoning** | Injected Host header values stored in cached responses, serving poisoned content to other users | Cache framework stores responses with Host-dependent content |
| **Password reset host injection** | The password reset email uses `request.get_host()` to construct the reset URL; Host header manipulation redirects reset links to attacker-controlled domains | No `ALLOWED_HOSTS` restriction or behind misconfigured proxy |

### §3-3. URL Validator Bypass

Django's `URLValidator` and IP address validators contain bypass vectors for SSRF and related attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Octal IP bypass (leading zeros)** | `URLValidator` accepted `0177.0.0.1` (octal for 127.0.0.1), bypassing SSRF blocklists | Application uses URLValidator to block internal IPs |
| **Newline injection via validators** | `URLValidator` and `EmailValidator` accepted newline characters, enabling header injection | Validated URLs used in HTTP requests or headers |
| **`reverse()` external URL generation** | `reverse()` could generate URLs pointing to external hosts via crafted URL patterns | Attacker-influenced URL namespace |

### §3-4. URL Path Access Control Bypass

URL routing mismatches between Django and upstream components create access control gaps.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trailing content bypass** | URLs with trailing content after the matched pattern bypass upstream access control that uses exact path matching | Reverse proxy ACL uses prefix matching differently than Django URL dispatch |
| **WSGI header spoofing** | Underscore/dash conflation in WSGI headers (e.g., `X-Auth-User` vs `X_Auth_User`) allows header spoofing | Application trusts WSGI-converted headers for authentication |

---

## §4. Authentication & Session Management

Django's auth system provides password hashing, session management, CSRF protection, and user administration. Vulnerabilities in this layer directly enable account takeover, privilege escalation, and authentication bypass.

### §4-1. Password Reset Exploitation

The password reset flow has been the target of multiple creative attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unicode case transformation takeover** | Email addresses with Unicode characters (e.g., `ß` → `ss` under case folding) match existing accounts but deliver reset tokens to attacker-controlled addresses | Application uses case-insensitive email matching with Unicode normalization |
| **Response status enumeration** | Password reset returns different HTTP status codes (200 vs 500) depending on whether the email exists, enabling user enumeration | Email backend misconfiguration causes 500 on send failure |
| **POST without token validation** | `PasswordResetConfirmView` in certain versions accepted POST requests without validating the reset token | Specific Django versions (master branch, 2016) |

### §4-2. User Enumeration

Timing and response differences reveal whether accounts exist.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Password hasher timing differential** | Login attempts against existing accounts with password hasher work factor upgrades take measurably longer than non-existing accounts | Hasher iteration count upgraded between Django versions |
| **Unusable password timing** | Users with unusable passwords (e.g., social auth) produce different timing than non-existing users | Application has users with unusable passwords |
| **mod_wsgi auth handler timing** | The `check_password` function in mod_wsgi authentication handler leaks timing information | Using Django's mod_wsgi auth handler |
| **AuthenticationForm information leak** | Error messages or response behavior differ based on whether the username exists | Default auth forms without custom error handling |
| **ORM QuerySet filter timing oracle** | Response time of `filter()` and `exists()` calls varies measurably depending on whether conditions match database rows. An attacker performs binary search over field values by observing latency differences, extracting data without direct output reflection | Endpoint exposes filtered QuerySet results; database query time proportional to match complexity; no constant-time abstraction over ORM responses |

### §4-3. CSRF Protection Bypass

Django's CSRF protection relies on token comparison between a cookie and a form/header value.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Subdomain cookie injection** | A subdomain can set CSRF cookies for the parent domain, then submit matching tokens | Untrusted subdomains exist on the same parent domain |
| **Google Analytics cookie override** | Google Analytics `utm_cookies` could overwrite the CSRF cookie on certain Django versions | Google Analytics enabled; specific cookie parsing behavior |
| **Anonymous CSRF exemption in DRF** | Django REST Framework's `SessionAuthentication` skips CSRF for unauthenticated requests, enabling CSRF on login and other unauthenticated POST endpoints | Using DRF with SessionAuthentication |
| **`@csrf_exempt` decorator** | Views decorated with `csrf_exempt` completely disable CSRF protection | Developer disables CSRF for API endpoints |
| **CSRF token caching leak** | Caching anonymous pages could reveal CSRF tokens if vary headers are not properly set | Cache framework caches pages containing CSRF tokens |

### §4-4. Privilege Escalation

Admin interface and permission system vulnerabilities that allow privilege boundary violations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`save_as=True` object creation** | Users with only "change" permission could create new objects via `ModelAdmin` with `save_as=True` | Admin ModelAdmin configured with save_as=True |
| **Admin history information leak** | Admin history log revealed existence and details of objects the user shouldn't access | Admin interface with model history enabled |
| **Admin querystring manipulation** | Manipulating querystring parameters in admin allowed access to related model data beyond intended scope | Admin with related object lookups |
| **Password hash disclosure** | "View only" admin users could see password hashes in the user admin | Admin with view-only permission on User model |
| **ORM `_connector` privilege escalation** | `filter(**request.GET.dict())` with `_connector=OR&is_superuser=True` grants admin access | Application uses dict expansion in queries (§1-1) |

### §4-5. Session Management Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session store flooding** | Repeated requests to `logout()` create new session entries, filling the session backend | No rate limiting on logout endpoint; database session backend |
| **Memory cache session manipulation** | Sessions stored in memory cache (memcached) can be manipulated if an attacker can influence cache keys | Memcached session backend with predictable keys |
| **`cached_db` session flushing** | Session data in `cached_db` backend could become inconsistent between cache and database | cached_db session backend |
| **RemoteUserMiddleware session hijacking** | `RemoteUserMiddleware` could allow session hijacking when the authentication header is manipulated between requests | REMOTE_USER-based authentication |

---

## §5. File Handling & Storage

Django's file upload, storage, and serving infrastructure creates attack surface for path traversal, denial of service, and code execution.

### §5-1. Path Traversal via Upload

Attackers craft filenames to write files outside intended upload directories.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Filename directory traversal** | Upload filenames containing `../../` sequences escape the upload directory | `MultiPartParser` insufficient filename sanitization |
| **`Storage.save()` traversal** | Custom storage backends' `save()` method may not validate against traversal when `generate_filename()` is overridden | Custom storage class without path validation |
| **Windows path separator** | Backslash (`\`) in filenames on Windows bypasses Unix-style traversal checks | Windows deployment; filename contains backslashes |
| **`archive.extract()` traversal** | Django's archive extraction (tar, zip) allows files with traversal paths to escape the extraction directory | Application extracts user-uploaded archives |
| **Nginx off-by-slash traversal** | Misconfigured Nginx `alias` directive with Django static file serving allows reading source code (e.g., `/static../manage.py`) | Nginx alias without trailing slash; Django static files |

### §5-2. File Upload Validation Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Multiple file upload bypass** | Validation applied to only the first file when multiple files are uploaded to a single field | Multi-file upload field with server-side validation |
| **File upload DoS** | Extremely large or numerous file uploads exhaust server memory/disk | No file size limits or upload throttling |
| **Reflected file download** | `FileResponse` with user-controlled filename in `Content-Disposition` header enables reflected file download attacks | Application sets filename from user input |

### §5-3. Static File Serving Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`django.views.static.serve()` traversal** | The static file serving view allowed directory traversal and DoS via crafted paths | Using serve() in production (contrary to Django docs) |
| **`admindocs` directory traversal** | The admin documentation module allowed reading arbitrary template files via path traversal | `admindocs` app installed and accessible |

---

## §6. HTTP Processing & Middleware

Django's HTTP request/response processing pipeline, including middleware, headers, and protocol handling, contains vulnerabilities related to header injection, cache behavior, and protocol-level attacks.

### §6-1. Header Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTTP response header injection** | `URLValidator` accepting newlines enabled CRLF injection into HTTP response headers | URLValidator-validated URLs used in response headers |
| **Email header injection** | Though Django protects against newlines in email headers, custom email construction may bypass this | Developer constructs email headers manually |
| **WSGI header spoofing** | Underscore-dash conflation in WSGI (HTTP_X_AUTH_USER for both `X-Auth-User` and `X-Auth_User`) allows header value overriding | Application trusts custom headers without prefix |
| **Log injection** | Unescaped request path components injected into log entries enable log forging and log injection attacks | Application or Django logs request paths without sanitization |

### §6-2. ASGI-Specific Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate header DoS** | `ASGIRequest` concatenates duplicate headers using string concatenation, causing super-linear computation with many duplicate headers | ASGI deployment; attacker sends many duplicate headers |

### §6-3. Cache Poisoning & Deception

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Host header cache poisoning** | Injected Host header values cached in responses, serving poisoned content | Cache framework + Host header manipulation |
| **Query parameter separator confusion** | `urllib.parse.parse_qsl()` accepting `;` as separator (CVE-2021-23336) enables cache key confusion | Caching layer uses `?` parameters as cache key |
| **Vary header misconfiguration** | Responses cached without proper `Vary` headers may serve personalized content to other users | Cache middleware without correct Vary configuration |
| **Private data caching** | Cache framework stored responses marked with private data, serving them to other users | Insufficient cache-control header management |
| **File system cache permission escalation** | Cache files created with overly permissive permissions on Python 3.7+ | File-based cache backend on multi-user systems |

### §6-4. Security Header Misconfiguration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing `X-Frame-Options`** | Clickjacking when `XFrameOptionsMiddleware` is not installed or `@xframe_options_exempt` is overused | Missing middleware or per-view exemptions |
| **Missing CSP** | Django does not include CSP middleware by default; applications lack Content-Security-Policy headers | No third-party CSP middleware configured |
| **Incorrect HTTPS detection** | Behind reverse proxies, Django may not correctly detect HTTPS, leading to insecure cookie transmission and mixed content | Reverse proxy without `SECURE_PROXY_SSL_HEADER` configuration |
| **Missing HSTS** | `SECURE_HSTS_SECONDS` not configured, allowing SSL stripping attacks | SecurityMiddleware installed but HSTS not enabled |

---

## §7. Serialization & Data Processing

Django's serialization layer — both internal (sessions, signing) and external (XML, JSON, YAML) — contains critical attack surface for RCE and DoS.

### §7-1. Pickle Deserialization RCE

The most severe Django vulnerability class when prerequisites are met.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session cookie deserialization** | With `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'` and a leaked `SECRET_KEY`, attackers forge session cookies containing malicious pickle payloads that execute arbitrary code on deserialization | PickleSerializer configured + SECRET_KEY leaked |
| **Signed cookie tampering** | Django's cookie signing uses `SECRET_KEY`; leaked key + pickle serializer enables forged cookies with RCE payloads | SECRET_KEY exposed via debug page, git, or misconfiguration |
| **Celery task deserialization** | Celery workers using pickle serializer for task arguments deserialize attacker-controlled payloads | Celery with pickle serializer; attacker can inject tasks |

**Attack Chain:**
```
SECRET_KEY leak (§8-1) → Forge session cookie with pickle RCE payload →
Arbitrary code execution on server
```

### §7-2. XML Processing Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XML External Entity (XXE)** | Python's `xml.sax` (with custom entity resolver) and `lxml` (when configured to resolve entities) are vulnerable to XXE file read and SSRF. `ElementTree`/`expat` do **not** resolve external entities but are vulnerable to entity expansion DoS (Billion Laughs). | Application processes XML from untrusted sources without `defusedxml` |
| **XML deserialization DoS** | Django's XML deserializer (used for fixtures and data import) exhibits algorithmic complexity on crafted XML with deeply nested or recursive entity definitions | Application uses Django's XML serializer with untrusted input |
| **Billion laughs / XML bomb** | Recursive entity expansion exhausts memory | XML processing without entity limits |

### §7-3. YAML Deserialization

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`yaml.load()` RCE** | Using `yaml.load()` instead of `yaml.safe_load()` allows arbitrary Python object construction, enabling RCE | Application processes YAML from untrusted sources |

---

## §8. Configuration & Information Disclosure

Django's configuration system, debug infrastructure, and deployment settings contain the highest-density surface for information disclosure that enables chained exploitation.

### §8-1. DEBUG Mode Exposure

Running Django with `DEBUG=True` in production transforms every error into a reconnaissance goldmine.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Settings exposure via traceback** | Error pages display all Django settings including database credentials, API keys, and SECRET_KEY | DEBUG=True in production |
| **Local variable exposure** | Stack traces expose local variables at each frame, potentially containing session data, passwords, and tokens | DEBUG=True; newer Django versions |
| **Route enumeration** | 404 pages list all URL patterns registered in the application | DEBUG=True in production |
| **SQL query exposure** | Debug toolbar and error pages display raw SQL queries including parameter values | DEBUG=True or django-debug-toolbar in production |
| **DNS rebinding via DEBUG** | With `DEBUG=True`, `ALLOWED_HOSTS` defaults to `['localhost', '127.0.0.1', '[::1]']`, but DNS rebinding can bypass this | DEBUG=True accessible from network |

### §8-2. SECRET_KEY Exposure

The `SECRET_KEY` is the cryptographic root of trust for Django's session signing, CSRF tokens, and password reset tokens.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hardcoded in settings.py** | SECRET_KEY committed to version control or stored in plaintext configuration | No environment variable or secrets manager |
| **Debug page leak** | Though Django attempts to hide SECRET_KEY in debug output, it can be recovered from local variables in stack frames | DEBUG=True + triggerable error |
| **Git repository exposure** | `.git` directory accessible via web server, revealing settings.py with SECRET_KEY | Web server serves .git directory |
| **Environment variable logging** | SECRET_KEY stored in environment variable but logged or exposed via `/proc` or debug endpoints | Insufficient environment isolation |

**Impact Chain:** SECRET_KEY → session forgery → account takeover (§7-1) or CSRF bypass (§4-3)

### §8-3. Admin Panel Exposure

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default admin URL (`/admin/`)** | Predictable admin URL enables targeted brute-force and credential stuffing | Default URL pattern; no rate limiting |
| **Admin login timing** | Login response timing reveals valid usernames | Default admin auth backend |
| **Content spoofing via 404** | Django's default 404 page reflected the request path, enabling content spoofing/phishing | Default 404 handler |

---

## §9. Input Validation & Form Processing

Django's form system, validators, and input processing utilities contain vulnerabilities in validation logic, mass assignment protection, and input processing performance.

### §9-1. Mass Assignment (Over-Posting)

Django's `ModelForm` can expose unintended fields to user modification.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`fields = '__all__'` exposure** | Using `Meta.fields = '__all__'` in ModelForm includes all model fields, including sensitive ones added later | ModelForm with fields='__all__' |
| **`exclude` list gap** | Using `Meta.exclude` instead of `Meta.fields` means new model fields are automatically exposed | ModelForm with exclude-based field list |
| **DRF Serializer over-exposure** | Django REST Framework serializers with `fields = '__all__'` or without explicit `read_only_fields` expose writable fields for privilege escalation | DRF serializer without field restriction |
| **`update()` with dict expansion** | `Model.objects.filter(...).update(**request.data)` allows modifying arbitrary fields | Application uses dict expansion in update() |

**Example:**
```python
# Dangerous — new fields auto-exposed
class UserForm(ModelForm):
    class Meta:
        model = User
        fields = '__all__'  # includes is_superuser, is_staff

# Safe — explicit whitelist
class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name']
```

### §9-2. Validator DoS (ReDoS)

Django's built-in validators use regular expressions susceptible to catastrophic backtracking.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **EmailValidator ReDoS** | Extremely long domain labels cause exponential regex processing in email validation | User-supplied email addresses without length pre-check |
| **URLValidator ReDoS** | Similar to EmailValidator; long domain portions trigger catastrophic backtracking | User-supplied URLs without length pre-check |
| **IPv6 validation DoS** | Lack of upper-bound limit in IPv6 validation allows DoS via extremely long strings | User-supplied IPv6 addresses |
| **`uri_to_iri()` DoS** | International URI conversion function exhibits super-linear behavior on crafted input | Processing untrusted URIs |
| **`get_supported_language_variant()` DoS** | Language variant lookup exhibits poor performance on crafted Accept-Language values | i18n enabled; processing untrusted Accept-Language |
| **`text.wrap()` DoS** | `django.utils.text.wrap()` exhibits poor performance on crafted input | User content processed with wrap() |

### §9-3. Formset Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`max_num` bypass** | Formset `max_num` validation could be bypassed to submit more forms than intended | Formset max_num not enforced server-side |
| **`UsernameField` DoS on Windows** | Username normalization using NFKC Unicode on Windows exhibits DoS behavior on certain inputs | Windows deployment; user registration |

### §9-4. SSRF via Input Validation Gaps

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URLField SSRF** | Server-side URL validation (formerly `verify_exists`) fetched URLs server-side, enabling SSRF | `URLField(verify_exists=True)` (removed in Django 1.4) |
| **Webhook callback SSRF** | Applications accepting callback URLs from users and making server-side requests | Application implements webhook functionality |
| **IP validation bypass** | Octal/hex IP representations (e.g., `0x7f000001` for 127.0.0.1) bypass blocklist-based SSRF protection | Application uses Django validators for SSRF prevention |

---

## §10. Attack Scenario Mapping (Axis 3)

| Scenario | Primary Architecture Conditions | Primary Mutation Categories |
|----------|-------------------------------|---------------------------|
| **Remote Code Execution** | SECRET_KEY leaked + PickleSerializer; or SSTI with dynamic templates | §7-1 + §8-2; §2-2 |
| **SQL Injection → Data Exfiltration** | Dict expansion in ORM calls; Oracle/PostgreSQL backend | §1-1, §1-2, §1-3, §1-4 |
| **Authentication Bypass** | ORM injection via `_connector`; password reset Unicode confusion | §1-1 + §4-1; §4-4 |
| **Account Takeover** | SECRET_KEY leak → session forgery; password reset host injection | §8-2 → §7-1; §3-2 + §4-1 |
| **Denial of Service** | Template filter DoS; validator ReDoS; ASGI header DoS | §2-3, §9-2, §6-2 |
| **Cross-Site Scripting** | Admin widget XSS; template escape bypass; debug page reflection | §2-1, §8-1 |
| **Path Traversal / File Access** | Upload filename traversal; archive extraction; Nginx misconfiguration | §5-1, §5-3 |
| **SSRF** | URLValidator bypass; webhook callbacks; IP representation tricks | §9-4, §3-3 |
| **Cache Poisoning** | Host header injection + caching; query parameter confusion | §6-3 + §3-2 |
| **Privilege Escalation** | Mass assignment; admin save_as; DRF serializer exposure | §9-1, §4-4 |
| **Information Disclosure** | DEBUG mode; settings leak via template filters; admin history | §8-1, §8-2, §2-4 |

---

## CVE / Bounty Mapping (2024–2026)

| Mutation Combination | CVE / Case | Severity | Impact |
|---------------------|-----------|----------|--------|
| §1-1 (_connector injection) | CVE-2025-64459 | **Critical (9.1, CISA-ADP)** | SQL injection via ORM query-structure manipulation; can enable auth/authz bypass depending on how QuerySet filters are built |
| §1-1 (FilteredRelation alias) | CVE-2025-57833 | High | SQL injection via column alias in annotate()/alias() |
| §1-1 (FilteredRelation PostgreSQL) | CVE-2025-13372 | Medium (4.3, CISA-ADP) | SQL injection in column aliases on PostgreSQL |
| §1-4 (annotate/alias MySQL) | CVE-2025-59681 | Critical (9.8, NVD) | SQL injection in annotate(), alias(), aggregate(), extra() on MySQL/MariaDB |
| §1-3 (HasKey Oracle) | CVE-2024-53908 | High | SQL injection via HasKey lookup on Oracle |
| §1-4 (values/values_list) | CVE-2024-42005 | High | SQL injection via QuerySet.values() and values_list() |
| §6-3 (raster PostGIS) | CVE-2026-1207 | Medium (5.4, CISA-ADP) | SQL injection via GIS raster band index on PostGIS; requires attacker influence over lookup parameters |
| §1-1 (column alias control chars) | CVE-2026-1287 | Medium (5.4, CISA-ADP) | SQL injection via control characters in column aliases; requires crafted dictionary expansion into QuerySet methods |
| §1-4 (order_by + FilteredRelation) | CVE-2026-1312 | Medium (5.4, CISA-ADP) | SQL injection via `order_by()` aliases containing periods with crafted FilteredRelation input |
| §2-3 (strip_tags DoS) | CVE-2025-32873 | Medium | DoS via nested HTML entities in strip_tags() |
| §2-3 (strip_tags DoS) | CVE-2024-53907 | Medium | DoS via large sequences in strip_tags() |
| §2-3 (urlize DoS) | CVE-2024-38875 | Medium | DoS in urlize() |
| §2-3 (urlize DoS) | CVE-2024-41990 | Medium | DoS in urlize() |
| §2-3 (urlize DoS) | CVE-2024-45230 | Medium | DoS in urlize() |
| §2-3 (Truncator ReDoS) | CVE-2024-27351 | Medium | ReDoS in Truncator.words() |
| §2-3 (floatformat memory) | CVE-2024-41989 | Medium | Memory exhaustion via floatformat() |
| §2-3 (Truncator HTML DoS) | CVE-2026-1285 | High (7.5, CISA-ADP) | DoS in Truncator HTML methods via many unmatched HTML end tags |
| §6-2 (ASGI header DoS) | CVE-2025-14550 | Medium | DoS via duplicate headers in ASGI |
| §3-1 (redirect DoS Windows) | CVE-2025-27556 | Medium | DoS in LoginView/LogoutView on Windows |
| §3-1 (redirect Unicode DoS) | CVE-2025-64458 | Medium | DoS via Unicode in redirect URLs |
| §5-1 (Storage.save traversal) | CVE-2024-39330 | Medium | Directory traversal via Storage.save() |
| §5-1 (archive.extract traversal) | CVE-2025-59682 | Medium | Directory traversal via archive extraction |
| §4-2 (password reset enumeration) | CVE-2024-45231 | Low | User email enumeration via password reset status |
| §4-2 (timing enumeration) | CVE-2024-39329 | Low | Username enumeration via timing for unusable passwords |
| §4-2 (mod_wsgi timing) | CVE-2025-13473 | Low | Username enumeration via mod_wsgi timing |
| §9-2 (IPv6 validation DoS) | CVE-2024-56374 | Medium | DoS via IPv6 validation |
| §9-2 (text.wrap DoS) | CVE-2025-26699 | Medium | DoS in text.wrap() |
| §7-2 (XML deserialization DoS) | CVE-2025-64460 | Medium | DoS in XML serializer text extraction |
| §6-1 (log injection) | CVE-2025-48432 | Medium | Log injection via unescaped request path |
| §2-3 (intcomma DoS) | CVE-2024-24680 | Medium | DoS in intcomma template filter |
| §9-2 (language variant DoS) | CVE-2024-39614 | Medium | DoS in translation language variant lookup |

---

## Detection Tools

### Static Analysis (SAST)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Bandit** (Python SAST) | raw(), extra(), pickle, eval, exec, SQL injection patterns | AST pattern matching; B610 detects QuerySet.extra() |
| **Semgrep** (Multi-language SAST) | Django-specific rules for SQLi, XSS, SSTI, insecure settings | Pattern-based code search with Django rulesets |
| **Pyre/Pysa** (Facebook) | Taint analysis for Django; tracks user input to dangerous sinks | Type-based taint flow analysis |
| **CodeQL** (GitHub) | Django SQL injection, XSS, path traversal queries | Semantic code analysis with dataflow tracking |
| **SonarQube** (Multi-language) | Django security hotspots, code smells, vulnerabilities | Rule-based analysis with Django plugins |

### Dynamic Analysis (DAST)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Nuclei** (ProjectDiscovery) | Django debug mode, admin exposure, CVE-specific templates | YAML-based template scanning |
| **django-security-check** | Django settings audit (DEBUG, SECRET_KEY, middleware) | Configuration analysis |
| **django-doctor** | Django anti-patterns, security issues in code | Linting-style detection |
| **DjangoHunter** | Django application fingerprinting and vulnerability detection | Recon + known vulnerability matching |

### Django-Specific Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **`manage.py check --deploy`** | Built-in deployment security checklist | Checks SECURE_*, DEBUG, ALLOWED_HOSTS, etc. |
| **django-axes** | Brute-force protection for admin login | Login attempt monitoring and lockout |
| **django-csp** | Content Security Policy header management | CSP header configuration and reporting |
| **django-cors-headers** | CORS policy enforcement | Cross-origin request validation |
| **defusedxml** | XXE/XML bomb prevention | Safe XML parser wrapper |
| **mozilla-django-oidc** | OAuth/OIDC authentication | Secure auth protocol implementation |

### Exploit / Research Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **django-rce-exploit** (Spix0r) | Pickle deserialization RCE via session cookies | SECRET_KEY + PickleSerializer exploitation |
| **django_token_exploit** | Password reset token generation/brute-force | Token algorithm analysis |
| **offbyslash-django-dumper** | Nginx off-by-slash source code dumping | Nginx alias misconfiguration exploitation |

---

## Summary: Core Principles

### The Root Cause: Trust Boundary Erosion Through Convenience APIs

Django's fundamental vulnerability pattern stems from the tension between **developer convenience** and **security isolation**. The framework provides powerful APIs — dictionary expansion into ORM methods, template auto-escaping opt-outs, flexible serializer backends — that create implicit trust boundaries. When user-controlled data crosses these boundaries via `**kwargs` expansion, `|safe` marking, or configuration-dependent serialization, the framework's layered defenses collapse.

The recurring SQL injection pattern (17+ CVEs) reveals a structural issue: Django's ORM generates different SQL across backends (PostgreSQL, Oracle, MySQL, SQLite), and each backend has unique parameterization gaps. Fixing a vulnerability on one backend doesn't protect others. The `**kwargs` expansion pattern (`filter(**request.GET.dict())`) is particularly insidious because it feels Pythonic and natural, yet it bridges the trust boundary between HTTP parameters and ORM internal control parameters (`_connector`, `_negated`).

### Why Incremental Patches Fail

Django's security team has demonstrated exceptional responsiveness (150+ CVEs fixed across 15+ years), but the patch pattern reveals structural limitations:

1. **Utility function DoS is whack-a-mole**: `strip_tags()`, `urlize()`, `Truncator`, `floatformat`, `intcomma` — each accepts unbounded input and exhibits super-linear behavior. Fixing one function doesn't prevent the same pattern in the next.

2. **Backend-specific SQL generation creates combinatorial explosion**: Each new ORM feature (FilteredRelation, JSONField lookups, GIS functions) must be audited across all supported databases. Oracle, PostgreSQL, and MySQL each require different escaping strategies.

3. **Dictionary expansion is inherent to Python**: The `**kwargs` pattern is fundamental to Python's design. Banning it in ORM calls requires either runtime enforcement (added in recent patches) or static analysis adoption.

### Structural Solutions

A comprehensive defense requires:

- **Explicit allowlisting** at every trust boundary: `Meta.fields = [...]` (not `'__all__'`), validated choices for ORM function arguments, explicit parameter allowlists for dict expansion
- **Input length bounds** before regex/HTML processing: Maximum length enforcement before passing to validators and template filters
- **Backend-agnostic parameterization audits**: Every ORM feature must be tested for SQL injection across all supported database backends
- **`manage.py check --deploy`** as CI gate: Built-in security checks should be mandatory in deployment pipelines, not optional
- **SECRET_KEY rotation and isolation**: Secrets management via environment variables with periodic rotation, combined with migration away from PickleSerializer

---

## References

- [Django Official Security Archive](https://docs.djangoproject.com/en/6.0/releases/security/)
- [Django Security Policy & HackerOne Program](https://hackerone.com/django)
- [OWASP Django Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html)
- [OWASP Django REST Framework Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html)
- [CVE Details — Django Product](https://www.cvedetails.com/product/18211/Djangoproject-Django.html)
- [Snyk Vulnerability Database — Django](https://security.snyk.io/package/pip/django)
- [Endor Labs — CVE-2025-64459 Analysis](https://www.endorlabs.com/learn/critical-sql-injection-vulnerability-in-django-cve-2025-64459)
- [CyCognito — CVE-2025-64459 Emerging Threat](https://www.cycognito.com/blog/emerging-threat-django-sql-injection-vulnerability-cve-2025-64459/)
- [ZeroPath — CVE-2025-57833 FilteredRelation Analysis](https://zeropath.com/blog/cve-2025-57833-django-filteredrelation-sql-injection)
- [Vidoc Security — Django Debug Mode Escalation](https://blog.vidocsecurity.com/blog/escalation-of-debug-mode-in-django)
- [Sangfor — CVE-2024-53908 Oracle HasKey Analysis](https://www.sangfor.com/farsight-labs-threat-intelligence/cybersecurity/cve-2024-53908-django-oracle-database-sql-injection)
- [Django Security Team — Recent Trends (2026)](https://www.djangoproject.com/weblog/2026/feb/04/recent-trends-security-team/)
- [PayloadsAllTheThings — SSTI Python](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)
- [StackHawk — Django SQL Injection Prevention](https://www.stackhawk.com/blog/sql-injection-prevention-django/)
- [StackHawk — Django Path Traversal Guide](https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/)
- [DryRun Security — Python Django SAST Comparison](https://www.dryrun.security/blog/dryrun-security-vs-snyk-codeql-sonarqube-and-semgrep---python-django-security-analysis-showdown)
- [SonarSource — Disclosing Information with a Side-Channel in Django (2022)](https://www.sonarsource.com/blog/disclosing-information-with-a-side-channel-in-django/)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
