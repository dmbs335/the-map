# WordPress Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

WordPress powers over 40% of the web, making it the single most targeted CMS platform. Its vulnerability surface is not monolithic — it spans core application logic, a vast plugin/theme ecosystem (96%+ of vulnerabilities), REST/XML-RPC API layers, authentication/authorization subsystems, database interaction patterns, file system operations, and the supply chain itself. In 2024 alone, 7,966 new WordPress vulnerabilities were disclosed (a 34% year-over-year increase), with XSS accounting for 47.7%, broken access control 14.19%, and CSRF 11.35%.

This taxonomy classifies the WordPress attack surface along three orthogonal axes:

- **Axis 1 — Mutation Target (WHAT is attacked)**: The structural component of the WordPress architecture being targeted — input handling, authentication logic, API endpoints, database queries, file operations, template rendering, cron/scheduling, caching layers, and the supply chain.
- **Axis 2 — Exploitation Mechanism (HOW it's exploited)**: The fundamental technique class — injection (XSS, SQLi, SSTI, PHP Object Injection), access control bypass (missing capability checks, nonce bypass, IDOR), logic flaws (race conditions, TOCTOU, parameter tampering), and configuration/information disclosure.
- **Axis 3 — Impact Scenario (WHAT is achieved)**: The operational outcome — Remote Code Execution, privilege escalation to admin, data exfiltration, site defacement, persistent backdoor, denial of service, lateral movement across multisite networks, and financial fraud.

### Axis 2 Summary — Cross-Cutting Exploitation Mechanisms

| Mechanism Class | Description | Primary §-Categories |
|----------------|-------------|---------------------|
| **Client-Side Injection** | XSS (Stored/Reflected/DOM) via unsanitized output | §1, §6 |
| **Server-Side Injection** | SQLi, SSTI, PHP Object Injection, Command Injection | §2, §5, §7 |
| **Access Control Bypass** | Missing capability checks, nonce failures, IDOR, auth bypass | §3, §4 |
| **Logic/State Flaws** | Race conditions, TOCTOU, parameter tampering, open redirects | §3, §8 |
| **File System Abuse** | Path traversal, unrestricted upload, extension bypass | §5 |
| **Supply Chain Compromise** | Backdoored plugins/themes, compromised update channels | §9 |
| **Configuration Exposure** | Debug mode leaks, wp-config.php exposure, user enumeration | §10 |
| **Caching/Proxy Abuse** | Cache poisoning, web cache deception | §8 |

---

## §1. Cross-Site Scripting (XSS) Mutations

XSS is the single most prevalent WordPress vulnerability class, accounting for nearly half of all disclosures. The WordPress ecosystem's reliance on user-generated content, plugin-rendered HTML, shortcodes, and block editor output creates an enormous surface for script injection.

### §1-1. Stored XSS via Plugin/Theme Input Fields

Stored XSS occurs when user-supplied input is persisted to the database and rendered without proper escaping on subsequent page loads. WordPress plugins frequently accept input through custom post types, meta fields, settings pages, and form submissions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Comment field injection** | Malicious script stored in comment content, rendered in admin dashboard or front-end | Missing `wp_kses()` or `esc_html()` on comment display |
| **Custom field / post meta injection** | Script injected via custom meta boxes or Advanced Custom Fields, executed when meta is displayed | Plugin renders meta without `esc_attr()` or `esc_html()` |
| **Settings page stored XSS** | Admin-level stored XSS via plugin settings that render unsanitized option values | `update_option()` stores raw input; `get_option()` output not escaped |
| **Form submission injection** | Contact form, registration form, or survey plugin stores and displays submissions with script tags | Input stored via `$wpdb->insert()` without sanitize, displayed without escape |
| **Widget/sidebar injection** | Scripts injected via widget configuration fields rendered on every page load | Widget `widget()` method outputs `$instance` values directly |

Stored XSS in plugins with large install bases (LiteSpeed Cache, WP Statistics, WP Meta SEO) has been actively exploited to inject SEO spam and credential-harvesting scripts into cached pages.

### §1-2. Reflected XSS via URL Parameters and Search

Reflected XSS occurs when user input in the HTTP request is immediately included in the response without proper escaping.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Search query reflection** | Search terms reflected in `<input value="">` or page title without escaping | `get_search_query()` used without `esc_attr()` |
| **URL parameter reflection** | GET/POST parameters echoed in error messages, redirects, or page content | Plugin reads `$_GET['param']` and outputs directly |
| **Admin notice reflection** | Action result messages in wp-admin reflect unsanitized parameters | `$_GET['message']` rendered in admin notices |
| **Pagination/filter parameter reflection** | Sort, filter, or page parameters reflected in table headers or navigation links | Plugin generates HTML links with raw `$_REQUEST` data |

### §1-3. DOM-Based XSS

DOM-based XSS occurs when client-side JavaScript reads from a DOM source (URL hash, `document.referrer`, `window.name`) and writes to a dangerous sink (`innerHTML`, `document.write`, `eval`).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hash fragment injection** | Plugin JS reads `location.hash` and inserts into DOM | jQuery `.html()` or vanilla `innerHTML` on hash data |
| **PostMessage handler abuse** | Plugin listens for `window.postMessage` and renders data without origin validation | `addEventListener('message', ...)` without origin check |
| **Third-party script injection** | Plugin loads external scripts that read URL parameters into DOM | Dependency on CDN-hosted libraries with DOM XSS sinks |

### §1-4. Stored XSS via Block Editor (Gutenberg)

The block editor introduces unique XSS surfaces through custom blocks, block attributes, and server-side rendering of block content.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Custom block attribute injection** | Malicious content in block attributes (`data-*`) rendered server-side | Block registration lacks proper attribute sanitization |
| **Block preview rendering** | Script injection via block preview that executes in contributor/author context | Block's `render_callback` outputs attributes without escape |
| **Reusable block poisoning** | Stored XSS in a reusable block propagates across all pages using it | Single injection point multiplied across the site |
| **Widget block injection** | Gutenberg widget blocks accept script input rendered in sidebar areas | Widget block's `save` function preserves raw HTML |

(CVE-2024-10178: Gutentor Countdown widget stored XSS; Gutenberg 21.7-21.8 stored XSS)

---

## §2. SQL Injection (SQLi) Mutations

WordPress provides `$wpdb->prepare()` as the primary defense against SQLi, but plugins frequently bypass this safeguard through direct query construction, improper placeholder usage, or second-order injection via stored values.

### §2-1. Direct (First-Order) SQL Injection

User-supplied input is directly concatenated into SQL queries without parameterization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **AJAX handler SQLi** | Plugin registers `wp_ajax_nopriv_*` action that builds query from `$_POST` data | No `$wpdb->prepare()` on `$wpdb->query()` |
| **REST API endpoint SQLi** | Custom REST endpoint reads request parameters into SQL WHERE clause | `$request->get_param()` used directly in query |
| **Shortcode attribute SQLi** | Shortcode callback uses attribute values in database queries | `[shortcode id="1 UNION SELECT..."]` parsed into query |
| **Search/filter parameter SQLi** | Plugin's custom search or filter functionality passes raw input to query | Custom `WP_Query` modifications via `posts_where` filter |
| **ORDER BY / LIMIT injection** | Sort column or pagination values injected into non-parameterizable clauses | `$wpdb->prepare()` cannot parameterize `ORDER BY`; raw input used |
| **Time-based blind SQLi** | No visible output; attacker infers data via response time differences | `SLEEP()` or `BENCHMARK()` injected into boolean conditions |

(CVE-2024-27956: WP Automatic plugin arbitrary SQL execution, 40K+ sites; CVE-2024-2879: LayerSlider CVSS 9.8; CVE-2025-9807: The Events Calendar time-based blind SQLi)

### §2-2. Second-Order SQL Injection

Malicious input is first stored in the database (via a legitimate operation) and later retrieved and used unsafely in a SQL query by a different code path.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stored meta → query injection** | Malicious value saved in `usermeta`/`postmeta`, later used in admin report query | Admin dashboard reads meta and builds aggregate query without escaping |
| **Option value → query injection** | Malicious setting stored via `update_option()`, later interpolated into SQL | Settings page stores raw input; cron job or backend process queries with it |
| **Import/export → query injection** | CSV/XML import stores payload in custom table; export or analytics query uses it unsafely | Importer sanitizes for XSS but not SQLi; downstream query trusts stored data |

### §2-3. WordPress-Specific SQLi Surfaces

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`$wpdb->prepare()` format string abuse** | Incorrect use of `prepare()` with `%s` inside `LIKE` or `IN()` clauses | `prepare("... LIKE '%{$var}%'")` instead of `prepare("... LIKE %s", '%' . $wpdb->esc_like($var) . '%')` |
| **`WP_Query` meta_query injection** | Unsanitized meta query values passed through `meta_query` arrays | Plugin constructs `meta_query` with user input in `value` field |
| **Tax query injection** | User-controlled taxonomy term slugs injected into `tax_query` | `$_GET['category']` passed directly to `tax_query` terms |

---

## §3. Authentication and Authorization Bypass Mutations

WordPress's authentication system relies on cookies, nonces, capability checks, and role-based access control. Plugins that implement custom authentication flows, API endpoints, or user management frequently introduce bypasses.

### §3-1. Authentication Bypass (Complete Auth Circumvention)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie-based identity assumption** | Plugin reads a cookie value (e.g., `original_user_id`) and authenticates as that user without verification | No HMAC/signature on cookie; attacker crafts `Cookie: original_user_id=1` (CVE-2025-5947) |
| **Predictable auto-login token** | Plugin generates login tokens using weak algorithms (MD5 of user ID) | Token = `md5(user_id)` without salt or expiration (CVE-2025-13390) |
| **API header bypass** | REST endpoint validates custom header (e.g., `ST-Authorization`) but accepts empty/missing values | `if (empty($header)) return;` skips auth instead of denying (CVE-2025-critical SureTriggers) |
| **Two-factor authentication bypass** | 2FA verification endpoint accepts crafted API calls that skip the second factor | Login API processes `user_id` parameter without requiring 2FA completion (CVE-2024-10924: Really Simple Security) |
| **WooCommerce platform checkout bypass** | Payment platform authentication function (`determine_current_user_for_platform_checkout`) trusts unauthenticated requests | Missing request origin validation in platform checkout flow |
| **Password reset token prediction** | Reset token generated with insufficient entropy or predictable seed | `wp_generate_password()` called with insufficient length; time-based seed |

### §3-2. Privilege Escalation (Authenticated → Higher Role)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **User meta role injection** | Profile update form allows setting `wp_capabilities` or role via `$_POST` | `update_user_meta()` processes arbitrary meta keys from form data (CVE-2024-8253) |
| **Registration role override** | Registration form/API accepts `role=administrator` parameter | `wp_insert_user()` called with user-controlled `role` field |
| **Arbitrary option update → admin creation** | Plugin allows subscribers to call `update_option()` on `default_role` or `users_can_register` | AJAX endpoint with `subscriber` capability check missing (CVE-2024-3895: WP Datepicker) |
| **Email change → account takeover** | Plugin allows changing any user's email without authorization, enabling password reset | AJAX handler updates email via `wp_update_user()` without ownership check (CVE-2024-8290: WCFM) |
| **JSON API user registration bypass** | JSON API endpoint allows setting administrator role via uncontrolled meta fields | Custom user meta processed without capability filtering (CVE-2024-6624) |
| **`set-screen-option` filter abuse** | Plugin misuses the `set-screen-option` filter to allow arbitrary user meta updates | Filter return value not validated, enabling `wp_capabilities` override |

### §3-3. Nonce and CSRF Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing nonce validation on state-changing actions** | AJAX handler performs privileged action without `check_ajax_referer()` | `wp_ajax_*` handler lacks nonce check entirely (CVE-2025-14163: Premium Addons) |
| **Conditional nonce check bypass** | Nonce is only verified if present: `if (isset($_POST['nonce'])) { verify... }` | Omitting the nonce parameter skips the entire check |
| **`check_admin_referer()` without action** | Using `check_admin_referer()` without specifying the nonce action accepts any valid nonce | Default behavior validates any `_wpnonce` regardless of action context |
| **Nonce without capability check** | Nonce validates that the request is intentional, but no `current_user_can()` check follows | Valid subscriber nonce executes administrator-level actions |
| **CSRF → file upload chain** | CSRF on theme import/plugin install endpoint allows attackers to upload malicious code | Admin tricked into visiting crafted page that triggers plugin installation (CVE-2025-12821) |

### §3-4. Insecure Direct Object Reference (IDOR)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sequential user ID enumeration** | `?author=1`, `?author=2` redirects reveal usernames; `/wp-json/wp/v2/users/` lists users | Default WordPress behavior; no plugin needed |
| **Post/page ID access bypass** | Draft or private posts accessible via direct ID parameter in API | REST endpoint returns content regardless of post status |
| **Payment/order ID enumeration** | WooCommerce order details accessible by incrementing order IDs | Missing ownership check in order view endpoint |
| **Form submission ID access** | Contact form entries accessible by sequential ID without authorization | Admin AJAX handler returns submission by ID without capability check |
| **Media attachment enumeration** | Private media files accessible via sequential attachment IDs | `?attachment_id=N` bypasses parent post access restrictions |

---

## §4. REST API and XML-RPC Attack Surface Mutations

WordPress exposes two major API surfaces: the modern WP REST API (`/wp-json/`) and the legacy XML-RPC interface (`xmlrpc.php`). Both present distinct mutation opportunities.

### §4-1. REST API Endpoint Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthenticated endpoint data leakage** | REST endpoints expose user data, post content, or site configuration without authentication | Default `wp/v2/users` endpoint enabled; plugins register public endpoints |
| **Missing `permission_callback` on custom endpoints** | Plugin registers REST route without specifying permission callback | `register_rest_route()` with `'permission_callback' => '__return_true'` or omitted |
| **Content injection via parameter type confusion** | REST API `id` parameter accepts non-numeric input, bypassing validation | `posts/111?id=111PAYLOAD` processed without strict type checking |
| **Shortcode execution via REST** | REST endpoint processes content through `do_shortcode()`, executing arbitrary shortcodes | Plugin renders user-supplied content with shortcode processing enabled (CVE-2024-13346: Avada) |
| **Batch endpoint abuse** | `/wp-json/batch/v1` combines multiple requests, amplifying attack surface | Batch processing bypasses per-endpoint rate limiting |

### §4-2. XML-RPC Attack Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Brute force amplification via `system.multicall`** | Hundreds of credential guesses bundled in a single `multicall` request | `xmlrpc.php` enabled with `system.multicall` available |
| **Blind SSRF via `pingback.ping`** | Server makes HTTP request to attacker-specified URL via pingback mechanism | `xmlrpc.php` pingback handler enabled; TOCTOU race in URL validation (CVE-2022-3590) |
| **DDoS amplification via pingback reflection** | Thousands of WordPress sites instructed to send pingback requests to victim | Publicly accessible `xmlrpc.php` with pingback enabled |
| **Content manipulation via `metaWeblog` / `wp.editPost`** | Authenticated XML-RPC methods used to modify posts, settings, or upload files | Valid credentials obtained via brute force; XML-RPC not restricted to IP |
| **User enumeration via `wp.getUsersBlogs`** | XML-RPC method used to verify username/password combinations | Method returns different error for invalid username vs. invalid password |

### §4-3. REST API + Plugin Interaction Chains

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Plugin installation via REST → RCE** | Unauthenticated REST endpoint allows plugin ZIP upload and activation | Plugin exposes `/install` endpoint without auth (CVE-2024-9707, CVE-2024-11972) |
| **REST → shortcode → SSRF chain** | REST endpoint renders shortcode → shortcode makes server-side HTTP request | `do_shortcode()` on REST input; shortcode uses `wp_remote_get()` with user URL |
| **REST → object injection → RCE** | REST endpoint passes input to `maybe_unserialize()` on stored data | Form data stored serialized; retrieval triggers `unserialize()` on attacker-controlled data |

---

## §5. File System and Upload Mutations

WordPress's media upload system, plugin/theme installation, and file management plugins create a substantial file system attack surface.

### §5-1. Unrestricted File Upload → Remote Code Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct PHP upload via plugin** | Plugin upload handler accepts `.php` files without extension validation | Custom upload endpoint uses `move_uploaded_file()` without `wp_check_filetype()` |
| **Extension blacklist bypass** | Attacker uploads `.phtml`, `.phar`, `.php5`, `.shtml`, or `.inc` files not in blacklist | Plugin checks against incomplete extension list; server executes non-standard PHP extensions |
| **Double extension bypass** | File named `shell.php.jpg` passes image validation but executes as PHP | Apache `mod_mime` processes first recognized extension; or misconfigured nginx |
| **`.htaccess` upload → extension remapping** | Attacker uploads `.htaccess` with `AddType application/x-httpd-php .shell`, then uploads `cmd.shell` | Directory allows `.htaccess` override; no AllowOverride restriction |
| **Null byte injection** | Filename `shell.php%00.jpg` truncates at null byte on older PHP versions | PHP < 5.3.4 with magic_quotes_gpc off |
| **MIME type mismatch** | File with PHP content has `image/jpeg` MIME type header; passes content-type validation but executes as PHP | Server routes by extension, not MIME; plugin validates MIME only |
| **Race condition file upload** | File temporarily accessible at predictable path during upload processing | Attacker requests temp file URL before validation/move completes (CVE-2024-7627: Bit File Manager) |

### §5-2. Path Traversal and Local File Inclusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Directory traversal via download handler** | Plugin's file download endpoint accepts `../../` sequences in filename parameter | `file_get_contents($upload_dir . $_GET['file'])` without path canonicalization (WordPress File Upload plugin) |
| **LFI via theme/template parameter** | Theme template loader accepts user-controlled path that escapes theme directory | `include($template_dir . $_GET['template'] . '.php')` |
| **wp-config.php read via traversal** | Path traversal reaches `wp-config.php`, exposing database credentials and auth keys | File download/view handler does not restrict to upload directory |
| **Symlink traversal** | File manager plugin follows symbolic links outside web root | `readfile()` or `file_get_contents()` follows symlinks without `realpath()` check |
| **Zip slip via plugin/theme upload** | Malicious ZIP archive contains entries with `../` paths, extracting files outside target directory | `ZipArchive::extractTo()` without path validation on archive entries |

### §5-3. Arbitrary File Deletion and Modification

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **wp-config.php deletion → site takeover** | Vulnerability allows deleting `wp-config.php`, triggering WordPress installer | Attacker completes fresh install with their credentials (CVE-2025-7384 chain) |
| **Plugin/theme file modification via editor** | WordPress built-in file editor allows direct PHP modification | `DISALLOW_FILE_EDIT` not defined; attacker has admin access |
| **Log file deletion for evidence destruction** | Attacker deletes access logs or security plugin logs via file manager vulnerability | File deletion endpoint without proper path restriction |

---

## §6. PHP Object Injection and Deserialization Mutations

WordPress's extensive use of `serialize()` / `unserialize()` for options, transients, and metadata creates a broad attack surface for PHP object injection.

### §6-1. Direct Deserialization of Untrusted Input

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie-based object injection** | Plugin reads serialized data from cookie and passes to `unserialize()` | `unserialize($_COOKIE['data'])` without validation (CVE-2024-4371: CoDesigner `recently_viewed_products` cookie) |
| **Form data deserialization** | Plugin stores serialized form submissions and unserializes on display | `unserialize($stored_data)` where stored data was user-controlled |
| **REST/AJAX parameter deserialization** | API endpoint accepts serialized PHP data as parameter value | `unserialize($request->get_param('data'))` |
| **Import file deserialization** | Plugin imports serialized data from uploaded files without validation | XML/JSON import contains serialized PHP objects |

### §6-2. Stored Deserialization (Second-Order)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **wp_options stored object injection** | Malicious serialized object stored in `wp_options` via `update_option()`, later unserialized | Plugin stores user input serialized; admin page or cron job `get_option()` + logic triggers `__wakeup()` |
| **Post meta stored injection** | Serialized payload stored in `wp_postmeta`, triggered when post is displayed or exported | Plugin saves `$_POST` data to meta; template calls `get_post_meta()` → `maybe_unserialize()` |
| **User meta stored injection** | Payload in `wp_usermeta` triggered during profile display or admin operations | User profile update stores serialized data; admin view triggers deserialization |
| **Transient stored injection** | Serialized payload in transient cache, triggered on `get_transient()` | Plugin caches API response as serialized object; `get_transient()` calls `maybe_unserialize()` |

### §6-3. POP Chain Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WordPress core POP chains** | Chains through WordPress core classes (`WP_Theme`, `WP_HTML_Token`, etc.) | Known POP chain gadgets present in WordPress core version |
| **Plugin-specific POP chains** | Gadget chains in installed plugins (e.g., GiveWP, Contact Form 7 DB) | Plugin includes classes with exploitable `__destruct()`, `__wakeup()`, or `__toString()` |
| **Cross-plugin POP chains** | Gadgets spanning multiple installed plugins to achieve RCE | Plugin A provides injection point; Plugin B provides gadget class |
| **File deletion via POP → reinstall RCE** | POP chain deletes `wp-config.php` → triggers installer → attacker completes setup | Chain achieves arbitrary file delete; no active session validation on installer (CVE-2025-7384) |

---

## §7. Server-Side Template Injection (SSTI) and Shortcode Abuse

WordPress's shortcode system and plugins that incorporate template engines (Twig, Blade, Smarty) create surfaces for server-side code execution.

### §7-1. Template Engine Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Twig SSTI via WPML** | WPML language switcher shortcode renders user-supplied Twig template | Shortcode content passed to Twig's `render()` without sandboxing (CVE-2024-6386: CVSS 9.9, 1M+ installs) |
| **Twig SSTI via Advanced Views** | Dynamic content rendering plugin executes Twig templates with user-controlled input | Author-level access can inject Twig payload: `{{['id']|filter('system')}}` (CVE-2025-10380) |
| **Blade template injection** | Plugin using Laravel Blade for templating accepts user input in template directives | `@php` or `{{ }}` expressions process unsanitized user data |
| **Smarty template injection** | Plugin using Smarty renders user-controlled template strings | `{php}` tags or `{system('id')}` in user-supplied content |

### §7-2. Shortcode Injection and Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Arbitrary shortcode execution** | Endpoint processes user content through `do_shortcode()` globally | Any registered shortcode can be invoked by attacker (CVE-2024-13346: Avada) |
| **Nested shortcode injection** | Shortcode attributes accept nested shortcode syntax that gets processed | `[shortcode attr="[malicious_shortcode]"]` → double-processed |
| **Shortcode → SSRF** | Shortcode that fetches remote content used to make server-side requests | `[embed url="http://169.254.169.254/..."]` or similar content-fetching shortcodes |
| **Shortcode → SQLi** | Shortcode attribute values passed to database queries | `[query id="1 OR 1=1"]` processed into `$wpdb->get_results()` |
| **Shortcode → information disclosure** | Shortcode renders private data (user info, settings, file contents) | `[user_data field="email" id="1"]` accessible by unauthenticated users |

---

## §8. Logic, State, and Caching Mutations

This category covers vulnerabilities arising from flawed application logic, race conditions, caching behavior, and state management.

### §8-1. Race Conditions and TOCTOU

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **File upload race condition** | File accessible at temporary path before validation completes | Predictable temp file path; no atomic move operation (CVE-2024-7627) |
| **Nonce double-use race** | Same nonce used in concurrent requests before invalidation | Nonce not consumed on first use; multiple windows accept same nonce |
| **SSRF TOCTOU via pingback** | URL validated at check time, changed via DNS rebinding before use | `pingback.ping` validates URL hostname, then makes HTTP request (CVE-2022-3590) |
| **Option update race** | Concurrent requests create race between `get_option()` and `update_option()` | Plugin reads option, modifies in PHP, writes back — not atomic |
| **Payment verification race** | WooCommerce payment status checked before payment fully processed | Order status updated asynchronously; race between status check and fulfillment |

### §8-2. Open Redirect

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`redirect_to` parameter abuse** | `wp-login.php` accepts `redirect_to` parameter with external URL | Insufficient validation of redirect target domain |
| **Plugin redirect manipulation** | Plugin's redirect after action (form submit, logout, purchase) accepts user-controlled URL | `wp_redirect($_GET['redirect_url'])` without `wp_safe_redirect()` |
| **OAuth callback redirect** | OAuth/social login plugin redirect URI can be manipulated | Redirect URI not validated against whitelist |
| **Post-authentication redirect chain** | Login → redirect → open redirect chain used for credential phishing | Trusted WordPress login page redirects to malicious domain |

### §8-3. Cache Poisoning and Deception

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **REST API cache poisoning via X-HTTP-Method-Override** | Sending X-HTTP-Method-Override header to REST API poisons cache with error responses | Cache stores error response for GET request; serves to all visitors |
| **Host header cache poisoning** | Malicious `Host` header causes WordPress to generate URLs with attacker's domain, cached and served to users | Cache key does not include `Host` header; `home_url()` uses `$_SERVER['HTTP_HOST']` |
| **Web cache deception via path confusion** | Request to `/my-account/profile.css` caches authenticated content as static asset | Cache serves `/my-account/profile.css` response (containing account data) to other users |
| **Caching plugin misconfiguration** | W3 Total Cache or LiteSpeed Cache caches pages with session-specific content | Cache configuration does not exclude authenticated user pages |
| **Plugin output cache poisoning** | Plugin caches rendered output that includes user-specific or attacker-controlled data | Cached HTML contains injected XSS payload; served to all visitors |

### §8-4. Business Logic Flaws

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WooCommerce coupon stacking** | Multiple discount codes applied beyond intended limits | Missing validation for coupon combination rules |
| **Payment amount tampering** | Cart total modified client-side before payment gateway submission | Server doesn't re-validate order total before processing (WooCommerce PayPal parameter tampering) |
| **Subscription bypass** | Membership/subscription plugin's access check bypassed via direct URL or API | Content restriction relies on template-level check, not server-side authorization |
| **Unauthenticated order creation** | WooCommerce allows creating orders without authentication | Missing auth check on order creation endpoint (pre-WooCommerce 9.4.3) |
| **Payment token exposure** | Stored credit card tokens accessible without authorization | Token retrieval function lacks ownership validation (CVE-2025-13457: WooCommerce Square, 80K+ sites) |

---

## §9. Supply Chain and Ecosystem Mutations

The WordPress plugin/theme ecosystem's open nature, centralized distribution through wordpress.org, and reliance on developer accounts create supply chain attack surfaces.

### §9-1. Plugin/Theme Repository Compromise

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Developer account takeover** | Attacker compromises wordpress.org developer account via credential stuffing, then pushes malicious update | Developer reuses passwords from breached databases (June 2024: 5 plugins compromised) |
| **Manual download compromise** | Attacker compromises website distribution channel (not WordPress.org auto-update) | Users who download ZIP manually receive backdoored version (July 2025: Gravity Forms) |
| **Abandoned plugin takeover** | Attacker acquires abandoned plugin (purchase or author transfer) and injects malicious code | Plugin with existing install base receives "update" containing backdoor |
| **Dependency injection** | Plugin's npm/composer dependency compromised; malicious code enters build pipeline | Build process includes compromised package; built artifacts contain backdoor |

### §9-2. Trojan Plugin Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fake security plugin** | Plugin named deceptively (e.g., "WP-antymalwary-bot.php") masquerades as security tool | Disguised as security tool; injects backdoor into `wp-cron.php` (January 2025) |
| **Hidden admin creation** | Malicious code creates admin user and exfiltrates credentials to C2 server | `wp_insert_user()` called with admin role during plugin activation |
| **SEO spam injection** | Backdoor injects hidden links/content into site footer for SEO spam | Payload injected via `wp_footer` hook; visible only to search engines (Cloaking) |
| **Crypto-mining payload** | Plugin includes JavaScript cryptocurrency miner in front-end output | Miner script loaded via `wp_enqueue_script()` on all pages |

### §9-3. Persistence Mechanisms

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **wp-cron.php backdoor** | Malicious plugin modifies `wp-cron.php` to re-create itself if deleted | Cron job runs every 1-3 minutes; downloads fresh payload from external server |
| **Must-use plugin (mu-plugin) backdoor** | Attacker places PHP file in `wp-content/mu-plugins/` — auto-loaded, no activation needed | `mu-plugins` directory writable; files execute on every page load |
| **Database-stored backdoor** | Malicious code stored in `wp_options` (e.g., `siteurl`, `active_plugins`, widget settings) | `eval(get_option('malicious_option'))` or XSS payload in widget HTML |
| **Theme `functions.php` injection** | Backdoor code appended to active theme's `functions.php` | Executes on every page; persists through plugin removal |
| **`.user.ini` / `php.ini` modification** | Attacker creates `.user.ini` with `auto_prepend_file` pointing to backdoor | PHP auto-loads attacker's file before every script execution |
| **Scheduled event persistence** | Attacker registers `wp_schedule_event()` that executes backdoor code periodically | Cron event persists in database; survives file-level cleanup |

---

## §10. Information Disclosure and Configuration Exposure Mutations

Information leakage provides reconnaissance data for subsequent attacks or directly exposes sensitive data.

### §10-1. Configuration and Credential Exposure

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **wp-config.php direct access** | Web server misconfiguration allows reading `wp-config.php` via HTTP | Incorrect server configuration; `.php` not processed; backup file `wp-config.php.bak` accessible |
| **Debug mode information leakage** | `WP_DEBUG` and `WP_DEBUG_DISPLAY` enabled in production expose full error traces | Error messages reveal file paths, database queries, plugin versions |
| **Database credential exposure** | wp-config.php backup, phpinfo(), or error messages reveal DB credentials | `wp-config.php~`, `wp-config.php.save`, or `.wp-config.php.swp` accessible |
| **Authentication key/salt exposure** | `AUTH_KEY`, `SECURE_AUTH_KEY`, etc., exposed via configuration file leak | Attacker can forge cookies and authenticate as any user |
| **phpinfo() exposure** | Plugin or test file calls `phpinfo()`, revealing full server configuration | Test files like `info.php` or `phpinfo.php` left in web root |

### §10-2. User and Content Enumeration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Author parameter enumeration** | `?author=N` redirects to `/author/username/`, revealing usernames | Default WordPress behavior; no plugin needed |
| **REST API user listing** | `/wp-json/wp/v2/users/` returns user IDs, usernames, and display names | Default endpoint enabled for unauthenticated access |
| **Login error message differential** | `wp-login.php` returns different errors for "invalid username" vs. "incorrect password" | Default WordPress behavior reveals valid usernames |
| **RSS/Atom feed author exposure** | Feed includes author display names and potentially email addresses | WordPress feeds enabled; author information not filtered |
| **XML sitemap enumeration** | WordPress sitemap (`/wp-sitemap.xml`) reveals site structure, post types, taxonomies | Sitemap enabled by default since WordPress 5.5 |

### §10-3. Version and Technology Fingerprinting

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Generator meta tag** | `<meta name="generator" content="WordPress X.X.X">` in page source | Default behavior; not removed by theme |
| **README.html / license.txt** | Static files reveal WordPress version and installation details | Files present in web root; accessible via HTTP |
| **Plugin/theme version in asset URLs** | `?ver=X.X.X` parameter in CSS/JS URLs reveals exact plugin versions | Default WordPress behavior for enqueued assets |
| **REST API version disclosure** | `/wp-json/` root endpoint reveals WordPress and REST API versions | Default endpoint enabled |
| **Feed version disclosure** | RSS/Atom feeds contain WordPress version information | `<generator>` tag in feed XML |
| **Login page fingerprinting** | `wp-login.php` design, error messages, and form structure identify WordPress | Standard WordPress login page not customized |

---

## §11. Multisite Network-Specific Mutations

WordPress Multisite introduces additional attack surfaces through shared infrastructure, cross-site trust relationships, and Super Admin privileges.

### §11-1. Cross-Site Escalation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Subsite admin → Super Admin escalation** | Stored XSS on subsite captures Super Admin session when they visit | Super Admin browses subsites; XSS executes in Super Admin session (CVE-2024-9883) |
| **Cross-site plugin injection** | Network-activated plugin vulnerability affects all sites simultaneously | Single vulnerability propagates across entire network |
| **Shared user table exploitation** | All sites share `wp_users` table; user creation on one site affects network | User registered on subsite gains access to network-wide user pool |
| **Database table prefix enumeration** | Multisite uses predictable table prefixes (`wp_2_`, `wp_3_`, ...) for subsites | SQL injection on one site can query other subsites' tables |

### §11-2. Network Administration Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Network-wide plugin activation** | Attacker with Super Admin access activates malicious plugin across all sites | Compromised Super Admin account; no change management |
| **Subdomain cookie scope abuse** | Cookies set on one subdomain readable by others in multisite | `COOKIE_DOMAIN` set to `.example.com`; session tokens shared across subsites |
| **Network theme manipulation** | Malicious theme pushed to all network sites via Super Admin | Theme `functions.php` backdoor propagates network-wide |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Unauthenticated RCE** | Public-facing WordPress with vulnerable plugin | §5-1 (file upload) + §6 (PHP OI) + §7-1 (SSTI) |
| **Subscriber → Admin Escalation** | WordPress with membership/registration enabled | §3-2 (privilege escalation) + §3-3 (CSRF) + §3-4 (IDOR) |
| **Complete Site Takeover** | Any WordPress installation | §3-1 (auth bypass) + §5-3 (wp-config deletion) + §6-3 (POP chain) |
| **Mass Exploitation via Supply Chain** | Thousands of sites with popular plugin | §9-1 (repo compromise) + §9-2 (trojan techniques) |
| **Data Exfiltration** | WooCommerce / membership sites | §2 (SQLi) + §3-4 (IDOR) + §8-4 (payment token exposure) |
| **Persistent Backdoor** | Previously compromised site | §9-3 (persistence: mu-plugins, wp-cron, .user.ini) |
| **DDoS Amplification** | Large number of WordPress sites as reflectors | §4-2 (XML-RPC pingback amplification) |
| **SEO Spam / Defacement** | Content-focused WordPress sites | §1 (stored XSS) + §9-2 (SEO injection) |
| **Credential Harvesting** | WordPress sites with login forms | §8-2 (open redirect) + §10-2 (user enumeration) + §4-2 (brute force) |
| **Multisite Network Compromise** | WordPress Multisite installation | §11-1 (cross-site escalation) + §1-1 (stored XSS) |
| **Financial Fraud** | WooCommerce stores | §8-4 (payment tampering) + §3-1 (checkout bypass) |
| **Cache-Based Attacks** | WordPress behind CDN/cache | §8-3 (cache poisoning/deception) |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §3-1 (auth bypass) + cookie manipulation | CVE-2025-5947 (Service Finder Bookings ≤6.0) | Admin account takeover; exploited day after patch |
| §3-1 (predictable token) | CVE-2025-13390 (WP Directory Kit ≤1.4.4) | Auth bypass via MD5(user_id) token prediction |
| §3-1 (2FA bypass) | CVE-2024-10924 (Really Simple Security, 4M+ sites) | Authentication bypass via crafted API call |
| §3-1 (API header bypass) | SureTriggers Plugin ≤1.0.78 (April 2025) | Admin account creation; exploited within 4 hours of disclosure |
| §2-1 (SQLi, unauthenticated) | CVE-2024-27956 (WP Automatic ≤3.92.0, 40K+ sites) | Arbitrary SQL execution |
| §2-1 (SQLi, CVSS 9.8) | CVE-2024-2879 (LayerSlider 7.9.11–7.10.0) | SQL injection via `ls_get_popup_markup` |
| §2-1 (blind SQLi) | CVE-2025-9807 (The Events Calendar) | Time-based blind SQLi, unauthenticated |
| §6-1 + §6-3 (PHP OI → POP → RCE) | CVE-2025-7384 (CF7 Database ≤1.4.3, CVSS 9.8) | Unauthenticated RCE via deserialization; wp-config.php deletion; 70K+ sites |
| §6-1 (cookie deserialization) | CVE-2024-4371 (CoDesigner ≤4.4.1) | PHP object injection via `recently_viewed_products` cookie |
| §6-2 + §6-3 (stored OI → RCE) | CVE-2024-8353 (GiveWP ≤3.16.3) | PHP OI → RCE in donation plugin, 100K+ installs |
| §6-1 (deserialization) | CVE-2026-0726 (Nexter Extension ≤4.4.6) | Unauthenticated PHP OI via `nxt_unserialize_replace` |
| §7-1 (Twig SSTI) | CVE-2024-6386 (WPML ≤4.6.12, CVSS 9.9, 1M+ installs) | RCE via Twig template injection in shortcode |
| §7-1 (Twig SSTI) | CVE-2025-10380 (Advanced Views ≤3.7.19) | Author-level RCE via SSTI |
| §5-1 (race condition upload) | CVE-2024-7627 (Bit File Manager 6.0–6.5.5) | Unauthenticated RCE via race condition |
| §5-2 (path traversal) | CVE-2024-32111 (WordPress Core 4.1–6.5.4) | Critical path traversal affecting millions |
| §5-1 (file upload) | WordPress File Upload Plugin ≤4.24.11 | Unauthenticated file read/delete via path traversal |
| §3-2 (user meta role injection) | CVE-2024-8253 (Post Grid Gutenberg Blocks) | Subscriber → administrator via meta update; 40K+ sites |
| §3-2 (email change → takeover) | CVE-2024-8290 (WCFM WooCommerce Manager) | Admin account takeover via email change; 20K+ sites |
| §3-2 (arbitrary option update) | CVE-2024-3895 (WP Datepicker) | Subscriber → admin via option manipulation; $493 bounty |
| §1-1 (stored XSS → privilege escalation) | CVE-2024-47374 (LiteSpeed Cache ≤6.5.0.2, 6M+ sites) | Unauthenticated stored XSS → admin takeover via single HTTP request |
| §3-3 (CSRF → file upload) | CVE-2025-12821 (NewsBlogger theme) | CSRF → arbitrary file upload → RCE |
| §8-4 (payment token exposure) | CVE-2025-13457 (WooCommerce Square ≤5.1.1) | Unauthenticated credit card token access; 80K+ sites |
| §9-1 (supply chain) | June 2024 (5 plugins via wordpress.org) | Developer accounts compromised; admin credential exfiltration |
| §9-1 (supply chain) | July 2025 (Gravity Forms 2.9.11.1) | Backdoor in manual download; 5M+ sites affected |
| §9-2 (trojan plugin) | January 2025 (WP-antymalwary-bot.php) | Fake security tool; wp-cron.php backdoor; admin access |
| §4-2 (SSRF TOCTOU) | CVE-2022-3590 (WordPress Core, all versions) | Blind SSRF via pingback.ping with TOCTOU race |
| §1-4 (Gutenberg stored XSS) | CVE-2024-10178 (Gutentor ≤3.3.x) | Stored XSS via Countdown widget |
| §3-1 (WooCommerce auth bypass) | WooCommerce Payments 4.8.0–5.6.1 | Unauthenticated privilege escalation |
| §8-3 (cache poisoning) | CVE-2025-9501 (W3 Total Cache) | RCE via critical caching plugin vulnerability; 1M+ installs |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **WPScan** (CLI scanner) | WordPress core, plugins, themes | Version fingerprinting against 64K+ vulnerability database; user enumeration; brute force |
| **Wordfence** (WAF + scanner) | Real-time protection + malware scanning | WAF rules, file integrity monitoring, IP reputation; 3,427 vulnerabilities published in 2024 |
| **Patchstack** (managed patching) | Virtual patching + vulnerability database | Priority scoring; received 4,853 valid reports in 2024; $16,400 record bounty |
| **Sucuri SiteCheck** (remote scanner) | External fingerprinting + malware detection | Remote HTTP-based checks for known malware signatures, blocklist status |
| **Nuclei** (template-based scanner) | WordPress detection + specific CVE checks | YAML templates for WordPress-specific vulnerabilities; `wordpress-detect.yaml` |
| **Burp Suite** (proxy/scanner) | Interactive testing + passive scanning | Proxy-based testing; custom extensions for WordPress-specific checks |
| **OWASP ZAP** (free scanner) | Automated scanning + active probing | Active scanner with WordPress-specific scan policies |
| **WPSec** (online scanner) | Remote WordPress vulnerability assessment | Online scanning service with automated reporting |
| **wp_admin_shell_upload** (Metasploit) | Authenticated RCE | Plugin upload mechanism exploitation via Metasploit framework |
| **xmlrpc-bruteforcer** (GitHub) | XML-RPC brute force | Multi-threaded brute force via `system.multicall` amplification |
| **WordPress Webshell Plugin** (GitHub) | Post-exploitation | Webshell disguised as legitimate plugin for authorized pentesting |
| **Pentest-Tools WordPress Scanner** (online) | Remote enumeration | Online WordPress-specific scanner with plugin/theme detection |

---

## Summary: Core Principles

### Why WordPress Is Uniquely Vulnerable

The WordPress vulnerability surface is fundamentally a **complexity/trust boundary problem**. WordPress core is relatively well-secured — only 7 core vulnerabilities were found in 2024 out of 7,966 total. The overwhelming attack surface (96%) resides in the **plugin and theme ecosystem**, where tens of thousands of independent developers implement security-critical operations (authentication, database queries, file handling, input sanitization) with varying levels of competence. WordPress's architecture grants plugins deep access to core functionality through hooks, filters, and direct database access via `$wpdb`, creating a situation where a single poorly-written plugin can compromise an otherwise hardened installation.

### Why Incremental Fixes Fail

The WordPress ecosystem suffers from three structural challenges that prevent incremental patches from eliminating the threat:

1. **Fragmented responsibility**: WordPress core provides secure APIs (`$wpdb->prepare()`, `wp_kses()`, `check_ajax_referer()`, `current_user_can()`), but plugins are not required to use them. There is no compile-time or runtime enforcement of secure coding patterns, meaning every plugin independently implements (or fails to implement) the same security patterns.

2. **Update lag**: Even when patches are released, adoption is slow. Many WordPress installations run outdated plugins, and the supply chain attacks of 2024-2025 demonstrate that even the update mechanism itself can be weaponized.

3. **Architectural trust**: Plugins share the same PHP execution context, database, and filesystem as WordPress core. There is no sandboxing, capability isolation, or resource restriction for plugins. A vulnerability in any active plugin has full access to the entire WordPress installation.

### What a Structural Solution Requires

A meaningful reduction in the WordPress attack surface would require: (a) **mandatory security enforcement** at the API level — making it impossible to construct SQL queries without parameterization, output HTML without escaping, or register endpoints without capability checks; (b) **plugin sandboxing** — isolating plugin execution so that a compromised plugin cannot access the broader filesystem, other plugins' data, or core WordPress tables beyond its declared scope; and (c) **automated supply chain verification** — cryptographic signing of plugin releases with multi-party validation, preventing single-point-of-failure account compromises from propagating malicious updates to millions of sites.

---

## References

- [Wordfence Threat Intelligence — WordPress Vulnerability Database](https://www.wordfence.com/threat-intel/vulnerabilities)
- [Patchstack — WordPress Vulnerability Statistics 2024](https://patchstack.com/database/statistics/wordpress/2024)
- [Patchstack — State of WordPress Security 2025](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2025/)
- [Patchstack — 2025 Mid-Year Vulnerability Report](https://patchstack.com/whitepaper/2025-mid-year-vulnerability-report/)
- [Wordfence — 2024 Annual WordPress Security Report](https://www.wordfence.com/wp-content/uploads/2025/04/2024-Annual-WordPress-Security-Report-by-Wordfence.pdf)
- [WPScan — WordPress Vulnerability Database](https://wpscan.com/)
- [Patchstack — Q1 2025 Most Exploited WordPress Vulnerabilities](https://patchstack.com/articles/new-year-new-threats-q1-2025s-most-exploited-wordpress-vulnerabilities)
- [Patchstack — Q3 2025 Most Exploited WordPress Vulnerabilities](https://patchstack.com/articles/q3-2025s-most-exploited-wordpress-vulnerabilities-and-how-patchstacks-rapidmitigate-blocked-them/)
- [Patchstack — Q4 2024 Most Exploited WordPress Threats](https://patchstack.com/articles/q4-2024-most-exploited-wordpress-threats)
- [Hadrian — CVE-2025-7384: Contact Form 7 DB Unauthenticated RCE](https://hadrian.io/blog/cve-2025-7384-critical-wordpress-plugin-unauthenticated-rce)
- [Hadrian — CVE-2025-9807: Events Calendar SQL Injection](https://hadrian.io/blog/cve-2025-9807-time-based-sql-injection-in-the-events-calendar-wordpress-plugin)
- [Hadrian — CVE-2024-13346: Avada Shortcode Abuse](https://hadrian.io/blog/exploiting-cve-2024-13346-shortcode-abuse-data-leaks-and-xss-in-wordpress)
- [WPSec — CVE-2024-10924: Really Simple Security Auth Bypass](https://blog.wpsec.com/the-full-story-of-cve-2024-10924-authentication-bypass-in-the-really-simple-security-plugin)
- [WPSec — CVE-2024-6386: WPML Twig SSTI RCE](https://blog.wpsec.com/the-full-story-of-cve-2024-6386-remote-code-execution-in-wpml/)
- [Stealthcopter — WPML RCE via Twig SSTI](https://sec.stealthcopter.com/wpml-rce-via-twig-ssti/)
- [ZeroPath — CVE-2025-10380: Advanced Views SSTI](https://zeropath.com/blog/cve-2025-10380-advanced-views-wordpress-plugin-ssti)
- [ZeroPath — CVE-2025-7384: CF7 Database PHP OI](https://zeropath.com/blog/cve-2025-7384-wordpress-contact-form-entries-php-object-injection)
- [Qualys — CVE-2024-31210: WordPress RCE via Plugin Upload](https://blog.qualys.com/vulnerabilities-threat-research/2024/04/15/wordpress-remote-code-execution-via-plugin-upload-cve-2024-31210)
- [Qualys — CVE-2024-10542: CleanTalk Anti-Spam](https://threatprotect.qualys.com/2024/11/28/wordpress-releases-fix-for-critical-vulnerability-impacting-anti-spam-plugin-cve-2024-10542/)
- [Qualys — CVE-2024-6386: WPML SSTI](https://threatprotect.qualys.com/2024/08/27/wordpress-plugin-wpml-multilingual-cms-server-side-template-injection-vulnerability-cve-2024-6386/)
- [Sonarsource — WordPress Core Unauthenticated Blind SSRF](https://www.sonarsource.com/blog/wordpress-core-unauthenticated-blind-ssrf/)
- [Wordfence — Supply Chain Attack on WordPress.org Plugins (June 2024)](https://www.wordfence.com/blog/2024/06/supply-chain-attack-on-wordpress-org-plugins-leads-to-5-maliciously-compromised-wordpress-plugins/)
- [BleepingComputer — WordPress Plugin Disguised as Security Tool (January 2025)](https://www.bleepingcomputer.com/news/security/wordpress-plugin-disguised-as-a-security-tool-injects-backdoor/)
- [BleepingComputer — Gravity Forms Supply Chain Attack (July 2025)](https://dev.ua/en/news/vidomyi-plahin-wordpress-stav-troianom-u-gravity-forms-vyiavyly-bekdor-1752677696)
- [Sucuri — Cron Job Abuse for Website Reinfection](https://blog.sucuri.net/2023/02/attackers-abuse-cron-jobs-to-reinfect-websites.html)
- [Cloudflare — WordPress Brute Force Amplification Attack](https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/)
- [HackerOne — WordPress Bug Bounty Program](https://hackerone.com/wordpress)
- [Patchstack — WordPress Bug Bounty Guide](https://patchstack.com/articles/wordpress-bug-bounty/)
- [Wordfence — Bug Bounty Program](https://www.wordfence.com/threat-intel/bug-bounty-program/)
- [HackTricks — WordPress Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)
- [Springer — Race Condition Vulnerabilities in WordPress Plug-ins (2024)](https://link.springer.com/chapter/10.1007/978-981-97-7737-2_10)
- [Wordfence — LiteSpeed Cache Stored XSS (CVE-2024-47374)](https://www.darkreading.com/endpoint-security/single-http-request-exploit-6m-wordpress)
- [GitHub — WordPress Core set-screen-option Filter Misuse (GHSA-4vpv-fgg2-gcqc)](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc)
- [Ryan Kozak — CVE-2025-13390: WP Directory Kit Auth Bypass](https://ryankozak.com/posts/cve-2025-13390/)
- [Vicarius — CVE-2024-27956: WP Automatic SQLi Analysis](https://www.vicarius.io/vsociety/posts/analyzing-sqli-exploit-for-wordpress-wp-automatic-plugin-for-fun-and-learning-cve-2024-27956)
- [SecurityWeek — 8,000 New WordPress Vulnerabilities in 2024](https://www.securityweek.com/8000-new-wordpress-vulnerabilities-reported-in-2024/)
- [ALM Corp — CVE-2025-13457: WooCommerce Square Credit Card Token Exposure](https://almcorp.com/blog/woocommerce-square-vulnerability-cve-2025-13457/)
- [CyberPress — W3 Total Cache RCE PoC (CVE-2025-9501)](https://cyberpress.org/poc-released-for-w3-total-cache-rce-vulnerability-exposing-1-million-websites/)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
