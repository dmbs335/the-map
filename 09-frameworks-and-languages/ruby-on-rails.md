# Ruby on Rails Vulnerability Mutation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire attack surface of Ruby on Rails applications under three orthogonal axes. **Axis 1 (Mutation Target)** defines *what structural component* of the Rails stack is being mutated — this is the primary organizational axis that structures the document body. **Axis 2 (Exploitation Mechanism)** captures *how the mutation achieves its effect* — the nature of the trust violation, parser mismatch, or unsafe default that makes the attack possible. **Axis 3 (Impact Scenario)** maps *where the mutation is weaponized* — the concrete attack outcome in a production deployment.

Ruby on Rails is a full-stack web framework that provides a deeply integrated pipeline from HTTP request parsing (Rack/Action Dispatch) through routing, controller processing (Action Controller), ORM operations (Active Record), template rendering (Action View), file handling (Active Storage), real-time communication (Action Cable), background processing (Active Job), and session/authentication management. Each layer introduces its own class of mutation targets, and the tight coupling between layers creates unique **cross-layer exploit chains** not found in more loosely-coupled architectures.

### Axis 2: Exploitation Mechanism Summary

| Mechanism | Description |
|-----------|-------------|
| **Trust Boundary Violation** | Unsanitized user input reaches a dangerous sink (eval, system, SQL, template) |
| **Unsafe Default Configuration** | Framework ships or operates with insecure defaults requiring explicit opt-in for safety |
| **Gadget Chain Exploitation** | Chaining existing Ruby/Rails code fragments to achieve arbitrary effects during deserialization |
| **Type/Format Confusion** | Unexpected data type or format accepted where a different type was assumed |
| **Parser Differential** | Framework-level parsing diverges from underlying library or OS behavior |
| **Access Control Bypass** | Authentication, authorization, or CSRF protections circumvented through structural weakness |
| **Resource Exhaustion** | Crafted input triggers catastrophic backtracking, memory exhaustion, or thread starvation |

### Axis 3: Impact Scenario Summary

| Scenario | Description |
|----------|-------------|
| **Remote Code Execution (RCE)** | Arbitrary command or code execution on the server |
| **Data Exfiltration** | Unauthorized read access to files, database records, or secrets |
| **Authentication/Authorization Bypass** | Gaining access without valid credentials or exceeding privilege boundaries |
| **Cross-Site Attack** | XSS, CSRF, or session-based attacks targeting end users |
| **Denial of Service (DoS)** | Application or infrastructure unavailability |
| **Cache/Response Poisoning** | Corrupting cached responses to affect other users |
| **Internal Service Access (SSRF)** | Reaching internal infrastructure through the application |

---

## §1. Deserialization & Object Marshaling

Deserialization vulnerabilities are the most critical class in the Rails ecosystem. Ruby's `Marshal`, `YAML`, and `JSON` deserialization mechanisms can instantiate arbitrary objects, invoke magic methods, and trigger gadget chains that lead to RCE. The tight integration of serialization throughout Rails — in sessions, caches, Active Job, Active Record columns, and Active Storage — creates an unusually large deserialization attack surface.

### §1-1. Marshal Deserialization

Marshal is Ruby's native binary serialization format. Calling `Marshal.load()` on untrusted input is equivalent to arbitrary code execution, as the deserialization process instantiates objects and invokes lifecycle methods that can be chained into gadget-based exploits.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Ruby 2.x Universal Gadget Chain** | Uses `Gem::Installer` and `Gem::SpecFetcher` classes from RubyGems standard library to chain through `method_missing` → `Kernel.open` for arbitrary command execution without requiring Rails-specific libraries | Marshal.load() on untrusted data; Ruby 2.x |
| **Ruby 3.x+ Gadget Chain** | Newer gadget chains discovered for Ruby 3.4 targeting updated standard library classes, bypassing patches applied to Ruby 3.2's `Gem::SafeMarshal` | Marshal.load() on untrusted data; Ruby ≥ 3.4 prior to patch |
| **Rails-Specific Gadget Chain** | Leverages Rails framework libraries (ActiveSupport, ActiveRecord) to construct exploit chains — e.g., `DeprecatedInstanceVariableProxy`, `ERB` template evaluation — that only exist in Rails environments | Marshal.load() in Rails app context |
| **Gem::SafeMarshal Escape** | Techniques to bypass Ruby 3.2+'s `Gem::SafeMarshal` allow-list protections by discovering new gadgets outside the blocked class list | Ruby ≥ 3.2 with SafeMarshal; novel gadget classes |
| **Session Cookie Deserialization** | When `CookieStore` is used as session storage and the `secret_key_base` / `secret_token` is known or leaked, an attacker can forge session cookies containing malicious Marshal payloads that the server deserializes | Known secret_key_base; CookieStore session backend |

**Example (Ruby 2.x Universal Gadget):**
```ruby
# Attacker crafts Marshal payload using Gem::Installer chain
payload = Marshal.dump(malicious_gadget_chain)
# Delivered via any endpoint that calls Marshal.load on user data
```

### §1-2. YAML Deserialization

YAML deserialization in Ruby historically used `YAML.load` (powered by Psych), which — like Marshal — could instantiate arbitrary Ruby objects via tagged YAML syntax (`!ruby/object`, `!ruby/hash`). Ruby 3.1+ defaults to `YAML.safe_load`, but legacy code and explicit `unsafe_load` calls remain exploitable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XML Parameter Parsing YAML Injection** | Rails XML parameter parser historically accepted YAML-tagged values within XML bodies, allowing deserialization of arbitrary objects via standard HTTP requests | Rails < 4.0 with XML parameter parsing enabled (CVE-2013-0156) |
| **YAML.load on User Input** | Direct use of `YAML.load` (pre-3.1 default) or `YAML.unsafe_load` (post-3.1) on attacker-controlled strings triggers object instantiation and code execution | Application code using YAML.load/unsafe_load |
| **Active Record Serialized Columns** | Active Record's `serialize` attribute uses YAML by default. If an attacker can write arbitrary data to a serialized column (e.g., via SQL injection), subsequent reads will deserialize malicious YAML into Ruby objects, escalating to RCE | SQL injection or direct DB access + YAML-serialized column (CVE-2022-32224) |
| **ERb-within-YAML Gadget** | YAML payloads construct `ERB` template objects whose `src` attribute contains arbitrary Ruby code, which executes when `result()` is called during deserialization | YAML.load on untrusted data with ERB in scope |

**Example (YAML payload for RCE):**
```yaml
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: "id"
       method_id: :resolve
```

### §1-3. JSON Deserialization

While JSON itself does not support arbitrary object instantiation, Rails' `JSON.parse` with `create_additions: true` or legacy `MultiJson` configurations can be exploited to instantiate objects via `json_class` keys.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON create_additions** | When `JSON.parse(input, create_additions: true)` is used, a `json_class` key in the JSON body triggers instantiation of the specified Ruby class | Explicit create_additions: true; suitable target class |
| **ActiveSupport JSON Decode** | Historical versions of `ActiveSupport::JSON.decode` would pass through to YAML parsing, enabling the YAML deserialization attack surface via JSON endpoints | Rails < 4.0 |

### §1-4. ActiveSupport MessageVerifier/MessageEncryptor

Rails uses `ActiveSupport::MessageVerifier` and `ActiveSupport::MessageEncryptor` for signed/encrypted messages (session cookies, signed GlobalIDs, etc.). These use Marshal as the default serializer, meaning a compromised signing key enables RCE via crafted payloads.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Secret Key Leakage → Cookie RCE** | If `secret_key_base` is leaked (via git exposure, error pages, path traversal), an attacker crafts a signed cookie with a Marshal RCE payload | Leaked secret_key_base; CookieStore; Marshal serializer |
| **GlobalID Deserialization in Active Job** | Active Job serializes arguments using GlobalID, which resolves to Active Record objects. Crafted GlobalID references can access unauthorized records or trigger deserialization of unexpected objects | Active Job accepting user-influenced arguments |
| **Weak HMAC Verification** | Timing attacks against HMAC comparison in older MessageVerifier implementations could enable forgery of signed messages | Pre-Rails 4 constant-time comparison |

### §1-5. Bootsnap Compile Cache Poisoning

Bootsnap (integrated into Rails since 5.2) accelerates application boot by caching compiled Ruby bytecode in `tmp/cache/bootsnap/compile-cache-iseq/`. Cache files consist of a 64-byte binary header (version, ruby_platform, compile_option, ruby_revision, size, mtime) followed by `RubyVM::InstructionSequence` binary data. When an attacker has arbitrary file write capability, overwriting a Bootsnap cache entry achieves RCE upon next application restart.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Compile Cache Overwrite** | Cache file paths are deterministic: FNV-1a-64 hash of the absolute source file path maps to a specific cache directory entry. An attacker crafts a cache file containing malicious `RubyVM::InstructionSequence.to_binary()` bytecode with a forged header, writes it to the calculated path, then triggers restart (e.g., via `tmp/restart.txt` for Puma). The poisoned cache loads before the legitimate source file | Arbitrary file write primitive + Bootsnap enabled (Rails ≥ 5.2 default) |
| **Black-Box Header Construction** | Cache validity depends on comparing header fields against the original source. All fields are deterministic per Ruby version and platform (version: 3–6, ruby_platform hash, compile_option CRC32, ruby_revision hash), enabling offline construction of valid cache files without direct access to the target environment | Knowledge of target Ruby version and platform |

---

## §2. Parameter Binding & Mass Assignment

Rails' automatic parameter binding — mapping HTTP request parameters to model attributes — is a core convenience feature that has historically been a rich source of vulnerabilities. The evolution from `attr_accessible`/`attr_protected` (Rails 3) to Strong Parameters (Rails 4+) mitigated but did not eliminate this attack surface.

### §2-1. Classic Mass Assignment

Before Strong Parameters, Rails models accepted all attributes by default unless explicitly blacklisted with `attr_protected` or whitelisted with `attr_accessible`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Attribute Overwrite** | Passing `user[admin]=true` or `user[role]=superadmin` in request parameters directly sets protected attributes on the model | Rails < 4.0 without attr_accessible; or attr_protected blacklist incomplete |
| **Association Injection via Nested Attributes** | `accepts_nested_attributes_for` extends mass assignment to associated models, allowing creation of entirely new records in referenced tables via `user[profile_attributes][...]` | Model with accepts_nested_attributes_for; missing reject_if validation |
| **Foreign Key Manipulation** | Setting `post[user_id]=1` allows reassignment of record ownership by directly overwriting foreign key columns | Foreign key column not excluded from mass assignment |

### §2-2. Strong Parameters Bypass

Strong Parameters (`require`/`permit`) in Rails 4+ moved the allowlist to the controller layer. However, several structural weaknesses remain.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **permit! (Permit All)** | Calling `.permit!` on parameters disables all filtering, equivalent to the pre-Rails 4 unprotected state | Developer uses params.permit! for convenience |
| **permit_all_parameters Global Flag** | Setting `ActionController::Parameters.permit_all_parameters = true` globally disables Strong Parameters for the entire application | Misconfiguration, often in development leaked to production |
| **Overly Broad Nested Permit** | Permitting nested hashes with `permit(preferences: {})` allows arbitrary keys within the nested structure, potentially overwriting unexpected attributes | Hash-type permit without explicit key list |
| **Non-Numeric Key Bypass** | Strong Parameters assumes nested attribute keys are numeric indices. Non-numeric keys (e.g., `NEW_RECORD`, timestamps) may bypass the numeric-only check, causing all passed records to be unpermitted or incorrectly permitted | Rails 5.0.x; non-numeric nested attribute keys |
| **Type Confusion via Array/Hash Swap** | Sending a hash where an array is expected (or vice versa) can confuse Strong Parameters validation logic, potentially allowing unfiltered values to pass through | Controller expects params[:items] as array but receives hash |
| **_json Parameter Juggling** | Rails wraps non-Hash JSON request bodies in `{ _json: data }` (in `ActionDispatch::Http::Parameters`). When a JSON request includes an explicit `_json` key alongside top-level parameters, authorization logic and action execution logic may resolve different parameter views from the same request — one preferring the top-level scalar form, the other the `_json` array form. This dual interpretation enables authorization bypass when multi-item and single-item code paths have divergent permission checks | JSON Content-Type request; inconsistent parameter resolution between authorization and action logic |

### §2-3. Class Pollution (Ruby's Prototype Pollution Analog)

Inspired by JavaScript prototype pollution, Ruby's class pollution exploits recursive hash merge operations to modify class-level attributes or method behavior.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ActiveSupport deep_merge Pollution** | `Hash#deep_merge` (from ActiveSupport) recursively merges nested hashes. When used with user input to update configuration or class-level attributes, attackers can overwrite unintended keys | deep_merge on user-controlled hash into class/config state |
| **Hashie::Mash Attribute Injection** | Hashie::Mash converts hash keys to method-like accessors. Keys ending in `_`, `!`, or `?` bypass merge protections, allowing attribute injection that modifies object behavior | Application using Hashie::Mash with user input |
| **OpenStruct Method Overwrite** | `OpenStruct.new(user_hash)` creates methods from hash keys, potentially overwriting critical methods like `class`, `send`, or `respond_to?` | OpenStruct initialized with user-controlled hash |

---

## §3. SQL Injection via ActiveRecord

ActiveRecord provides a rich query interface that safely parameterizes most operations. However, numerous methods accept raw SQL strings, and the boundary between "safe" and "unsafe" usage is subtle. The rails-sqli.org project documents dozens of injectable method signatures across Rails versions.

### §3-1. Direct SQL String Injection

Methods that accept raw SQL strings without parameterization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **where(string)** | `User.where("name = '#{params[:name]}'")` directly interpolates user input into SQL | String interpolation in where clause |
| **where(string, *binds) Misuse** | Using string interpolation instead of bind parameters: `where("name = '#{v}'")` instead of `where("name = ?", v)` | Developer uses interpolation instead of placeholders |
| **order/reorder Injection** | Prior to Rails 6, `order()` and `reorder()` accepted arbitrary SQL strings, enabling injection via ORDER BY — exploitable using CASE statements for data extraction | Rails < 6.0; user input in order() |
| **group Injection** | `group()` accepts arbitrary SQL strings, allowing injection into GROUP BY clauses | User input passed to group() |
| **from Injection** | `from()` accepts arbitrary SQL, replacing the FROM clause entirely — allowing subquery injection or table substitution | User input passed to from() |
| **pluck Injection** | Prior to Rails 6.1, `pluck()` accepted arbitrary SQL, allowing complete control from SELECT onwards | Rails < 6.1; user input in pluck() |
| **having Injection** | `having()` accepts raw SQL strings for HAVING clauses | User input passed to having() |
| **joins(string) Injection** | String-form joins accept arbitrary SQL in the JOIN clause | User input in joins() string argument |
| **select(string) Injection** | Raw SQL in `select()` allows manipulation of the SELECT clause, potentially extracting data from other columns or tables | User input in select() |

### §3-2. Conditional/Dynamic Query Injection

Injection through dynamically constructed query conditions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hash Condition Key Injection** | `where(params[:column] => value)` allows the attacker to control which column is queried, potentially accessing columns not intended for filtering | User-controlled hash key in where condition |
| **Arel SQL Literal Injection** | `Arel.sql(user_input)` explicitly marks input as safe SQL, bypassing all ActiveRecord protections — acts as a direct injection sink | Developer wraps user input in Arel.sql() |
| **find_by_sql / count_by_sql** | These methods accept complete SQL statements, providing no parameterization — any user input is directly embedded | User input in find_by_sql/count_by_sql |
| **calculate with SQL** | Aggregate methods (`sum`, `average`, `minimum`, `maximum`) accept raw SQL field arguments | User input in aggregate method field argument |
| **delete_all / update_all String Form** | `delete_all("condition")` and `update_all("set_clause")` accept raw SQL strings for conditions or SET clauses | User input in delete_all/update_all string argument |

### §3-3. Scope and Relation Injection

SQL injection through Rails scopes, relations, and query chaining.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dynamic Scope Injection** | Scopes that accept parameters and interpolate them into SQL: `scope :by_name, ->(name) { where("name LIKE '%#{name}%'") }` | Scope with string interpolation |
| **Ransack/Searchkick Parameter Injection** | Search gems that translate parameter hashes into queries may allow injection through specially crafted search parameter keys or values | Ransack, Searchkick, or similar search gems without strict parameter filtering |
| **exists? with SQL** | `Model.exists?(["name = '#{input}'"]) ` accepts raw SQL conditions | User input in exists? SQL condition |

---

## §4. Template Rendering & View Layer

Rails' view layer (Action View) uses ERB, Haml, or Slim templates. The framework provides automatic HTML escaping by default (since Rails 3), but numerous bypass mechanisms exist. Server-Side Template Injection (SSTI) is possible when user input reaches the template engine for evaluation.

### §4-1. Server-Side Template Injection (SSTI)

SSTI occurs when user-controlled data is embedded directly into a template and evaluated as code by the template engine.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ERB Inline Evaluation** | User input containing `<%= system('id') %>` is passed to `ERB.new(user_input).result`, executing arbitrary Ruby code | User input rendered through ERB.new().result |
| **render inline:** | `render inline: params[:template]` treats user input as an ERB template, enabling arbitrary code execution | User-controlled string passed to render inline: |
| **render template: with user input** | `render template: params[:page]` allows template path manipulation, potentially rendering unintended templates or reading arbitrary files | User input in render template: path |
| **Haml/Slim Injection** | When Haml (`Haml::Engine.new(input).render`) or Slim templates process user input, Ruby code within `#{}` or `=` blocks executes | User input rendered through Haml/Slim engine |

### §4-2. Cross-Site Scripting (XSS) Bypass

Rails 3+ auto-escapes all output in templates by default. XSS occurs when developers explicitly bypass this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **html_safe Marking** | Calling `.html_safe` on a string marks it as safe for rendering, bypassing HTML escaping entirely: `user_input.html_safe` | Developer calls html_safe on user-controlled data |
| **raw() Helper** | `raw(user_input)` is an alias for `.html_safe`, disabling escaping | Developer uses raw() with user input |
| **<%== %> Double-Equals Tag** | The `<%== %>` ERB tag is an alias for `html_safe`, rendering content without escaping | Template uses <%== %> with user data |
| **content_tag Attribute Injection** | `content_tag(:a, "click", href: user_input)` can inject `javascript:` protocol URIs or data: URIs in href attributes | User input in content_tag URL attributes |
| **link_to with javascript: Protocol** | `link_to "click", params[:url]` allows injection of `javascript:alert(1)` via the URL parameter | User input as link_to href |
| **sanitize Helper Bypass** | The `sanitize` helper has had multiple bypass vulnerabilities over the years. Crafted HTML/CSS can escape the sanitizer's allow-list to execute JavaScript | Rails-html-sanitizer < patched version (CVE-2024-53985, CVE-2022-23519, CVE-2022-32209) |
| **JSON Embedding in Script Tags** | Embedding model data in `<script>` tags via `to_json` without proper escaping can introduce XSS when JSON contains `</script>` or HTML entities | Inline JSON rendering without json_escape |
| **ActionText Rich Content XSS** | `ActionText::Attachable::ContentAttachment` instances within `rich_text_area` tags could contain unsanitized HTML | ActionText with unvalidated attachable content |

### §4-3. Dynamic Render Vulnerabilities

Rails' `render` method has numerous options that, when combined with user input, create file read, SSTI, or information disclosure vulnerabilities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **render file: Path Traversal** | `render file: params[:path]` allows traversal to arbitrary filesystem paths: `../../../../../../etc/passwd` | User input in render file: argument (CVE-2019-5418) |
| **Accept Header Format Injection** | Crafted HTTP Accept headers (e.g., `../../etc/passwd{{`) force Action View to resolve template paths via directory traversal when `render file:` is used without explicit format | render file: without formats: option (CVE-2019-5418) |
| **render with Arbitrary Format** | `render` without explicit format specification uses the request's Accept header to determine output format, potentially triggering rendering pipelines for unexpected content types | Missing explicit format in render calls |

---

## §5. File & Path Operations

Rails applications handle files through multiple layers: Active Storage for uploads, `send_file`/`send_data` for downloads, and various filesystem operations. Path traversal and command injection through file operations constitute a significant attack surface.

### §5-1. Path Traversal

Traversal attacks exploit insufficient path validation to read, write, or delete files outside intended directories.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **send_file Traversal** | `send_file(params[:filename])` without path validation allows `../../etc/passwd` to read arbitrary files | User input in send_file path |
| **send_data with User Filename** | While `send_data` itself serves content from memory, user-controlled filenames in the `Content-Disposition` header can enable response splitting or download confusion | User input in send_data filename |
| **File.read/File.open Traversal** | Application code using `File.read(params[:path])` or `File.open(params[:path])` without sanitization | User input in filesystem read operations |
| **Sprockets Asset Pipeline Traversal** | Path traversal in the Sprockets asset pipeline allows access to files outside the asset directories via manipulated asset paths | Sprockets serving assets with insufficient path validation (CVE-2018-3760) |
| **Rack::Static Path Traversal** | Rack's static file serving middleware concatenates URL paths with the root directory without validation. When `root` is misconfigured or defaults to `Dir.pwd`, traversal sequences access arbitrary files | Rack::Static with misconfigured :root (CVE-2025-27610) |
| **Active Storage Variant Path Manipulation** | Manipulating Active Storage variant transformation parameters to inject path characters or shell commands into image processing pipelines | Active Storage with user-controlled variant params |

### §5-2. Active Storage Command Injection

Active Storage integrates with image processing libraries (MiniMagick, Vips) for image transformations. When transformation parameters are user-controlled, command injection through ImageMagick is possible.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Transformation Method Injection** | Active Storage's default allow-list contained methods (`apply`, `loader`, `saver`) that could pass unvalidated options to MiniMagick, enabling shell command injection via ImageMagick's delegate processing | Active Storage + MiniMagick + user-controlled transformation params (CVE-2025-24293) |
| **Variant Parameter Injection** | `blob.variant(params[:t] => params[:v])` allows arbitrary transformation method/argument pairs, potentially invoking unsafe ImageMagick operations | Untrusted input in variant() method/argument |
| **ImageMagick Delegate Exploitation** | ImageMagick processes certain file types through external "delegates" (e.g., ghostscript for PDF). Crafted files can trigger command execution through delegate processing | Active Storage processing untrusted file uploads via ImageMagick |

### §5-3. File Upload Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content-Type Bypass** | Uploading files with manipulated MIME types to bypass file type validation, potentially uploading executable content (e.g., `.html` file with `image/png` content type) | MIME-type-only validation without content inspection |
| **Filename Injection** | Uploaded filenames containing path traversal sequences (`../`), null bytes, or shell metacharacters can exploit downstream processing | Unsanitized original_filename usage |
| **Polyglot File Upload** | Files that are valid in multiple formats simultaneously (e.g., GIF+JS polyglot) bypass content-type validation while being exploitable in a different rendering context | Content-type validation without content analysis |

---

## §6. Session & Authentication State

Rails provides session management, CSRF protection, and authentication helpers. Structural weaknesses in these mechanisms can lead to session hijacking, authentication bypass, and cross-site request forgery.

### §6-1. Session Management Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session Fixation** | If a new session identifier is not issued after login, an attacker can set a known session ID (via URL parameter or cookie injection) before the victim authenticates, then use that ID to access the authenticated session | Missing `reset_session` after authentication |
| **CookieStore Information Disclosure** | `CookieStore` (Rails default) stores the entire session payload in the cookie, encrypted but client-accessible. Session data may leak to the client through decryption if the secret is compromised | CookieStore + secret_key_base leakage |
| **EncryptedFile Temporary Exposure** | `ActiveSupport::EncryptedFile` writes decrypted contents to a temporary file with default umask permissions, allowing other users on the same system to read secrets during editing | Multi-user system; EncryptedFile editing |
| **Replay Attack on Signed Cookies** | Signed cookies (without encryption) can be replayed across sessions. Items previously removed from the session may be restored by replaying an old cookie | CookieStore without encryption; no server-side session tracking |

### §6-2. CSRF Protection Bypass

Rails' CSRF protection uses authenticity tokens embedded in forms and verified on non-GET requests. Several bypass mechanisms exist.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Token Masking XOR Weakness** | Rails masks CSRF tokens by XORing with a one-time pad and concatenating both. An attacker who captures a masked token can extract the raw token by reversing the XOR, since both key and ciphertext are present | Token capture via XSS or network interception |
| **Content-Type Based Bypass** | CSRF checks historically only applied to `application/x-www-form-urlencoded` and `multipart/form-data`. Requests with other content types (e.g., `text/plain`, `application/json`) could bypass verification | CSRF protection not applied to all content types |
| **Plugin/Redirect CSRF** | Browser plugins and HTTP redirects can be combined to forge cross-domain requests that bypass the same-origin checks of CSRF tokens | Vulnerable browser plugin + redirect chain (CVE-2011-0447) |
| **Permissions-Policy Content-Type Gap** | The Permissions-Policy security header is only served on HTML Content-Type responses, leaving non-HTML endpoints unprotected | Rails ≥ 6.1 serving API endpoints (CVE-2024-28103) |
| **skip_before_action :verify_authenticity_token** | API controllers often disable CSRF protection entirely, but if they share sessions with web controllers, the CSRF bypass becomes exploitable | API controller with session-based auth + CSRF disabled |

### §6-3. Authentication Weaknesses

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Timing Attack on Password Comparison** | Non-constant-time string comparison in password verification reveals password length or character matches through response time differences | Custom auth not using `secure_compare` |
| **has_secure_password Enumeration** | Default `has_secure_password` error messages differ between "user not found" and "wrong password", enabling username enumeration | Default error messages not unified |
| **Remember Token Predictability** | Weak random generation for remember-me tokens allows prediction | Custom remember token not using `SecureRandom` |

---

## §7. HTTP Request Processing & Routing

The HTTP processing pipeline (Rack → Action Dispatch → Router → Controller) introduces vulnerabilities through header manipulation, URL parsing, routing configuration, and response handling.

### §7-1. Host Header Injection & Open Redirect

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Forwarded-Host Trust** | Rails unconditionally trusted the `X-Forwarded-Host` header in `url_for` and all URL helpers until Rails 6, allowing cache poisoning and redirect manipulation | Rails < 6.0; proxy setting X-Forwarded-Host |
| **Host Authorization Middleware Bypass** | The HostAuthorization middleware in Action Pack can be tricked by specially crafted Host headers combined with certain allowed_hosts patterns, causing redirects to attacker-controlled sites | Action Pack < 6.1.2.1 (CVE-2021-22881) |
| **redirect_to Open Redirect** | `redirect_to(params[:url])` without validation allows redirection to attacker-controlled external sites for phishing | User input in redirect_to without allow_other_host: false |
| **redirect_to Header Injection** | The `redirect_to` method allowed characters illegal in HTTP header values, potentially causing downstream services to strip the Location header or inject additional headers | Rails allowing non-RFC-compliant header characters |
| **url_for Cache Poisoning** | Poisoning the `X-Forwarded-Host` header causes `url_for` to generate URLs pointing to the attacker's domain. If the response is cached, all subsequent users receive poisoned URLs | Caching proxy + Rails trusting X-Forwarded-Host |

### §7-2. Regular Expression Denial of Service (ReDoS)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Accept Header ReDoS** | Crafted Accept headers trigger catastrophic backtracking in Action Dispatch's Accept header parsing regular expressions | Rails 7.1.0–7.1.3.0; Ruby < 3.2 (CVE-2024-26142) |
| **Action Mailer block_format ReDoS** | Crafted text input to the `block_format` helper causes exponential regex backtracking | Rails ≥ 3.0 prior to patches; Ruby < 3.2 |
| **Action Text Blockquote ReDoS** | The `plain_text_for_blockquote_node` helper in Action Text is vulnerable to ReDoS via specially crafted text content | Action Text; Ruby < 3.2 (CVE-2024-47888) |
| **Cookie + X-Forwarded-Host ReDoS** | Specially crafted cookies combined with X-Forwarded-Host headers trigger catastrophic backtracking in middleware regex processing | Vulnerable middleware regex parsing |

### §7-3. Routing Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Route Globbing Information Disclosure** | Wildcard route segments (`*path`) capture everything including path traversal sequences, potentially exposing routes to unintended file access | Glob routes feeding into file operations |
| **Constraint Bypass** | Route constraints using regex without anchoring (e.g., `constraints: { id: /\d+/ }` vs `/\A\d+\z/`) can be bypassed with mixed alphanumeric input | Unanchored regex constraints |
| **HTTP Verb Override** | Rails supports `_method` parameter to override HTTP method for browsers that only support GET/POST. This can be abused to invoke PUT/DELETE/PATCH actions via POST requests | _method parameter spoofing |
| **Default Route Exposure** | Legacy default routes (`match ':controller(/:action(/:id))'`) expose all controller actions as URLs, including those intended to be internal | Legacy default route configuration |

---

## §8. Command Injection

Ruby provides numerous methods for executing system commands. When user input reaches any of these sinks, arbitrary command execution is possible. Rails applications are particularly vulnerable when processing user-uploaded files, generating reports, or interfacing with system utilities.

### §8-1. Direct Command Execution Sinks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **system() Injection** | `system("convert #{params[:file]}")` allows injection via shell metacharacters (`;`, `|`, `&&`, `` ` ``) | User input in system() string argument |
| **Backtick Injection** | `` `echo #{user_input}` `` executes interpolated input as shell commands | User input in backtick expression |
| **exec() Injection** | `exec("cmd #{input}")` replaces the current process with the command, including injected payload | User input in exec() string |
| **%x() Injection** | `%x(command #{input})` is syntactic sugar for backtick execution | User input in %x() expression |
| **IO.popen Injection** | `IO.popen("cmd #{input}")` opens a subprocess with the interpolated command | User input in IO.popen() |
| **Process.spawn Injection** | `Process.spawn("cmd #{input}")` spawns a new process with the injected command | User input in Process.spawn() |
| **Open3 Injection** | `Open3.capture2("cmd #{input}")` when using single-string (shell) form instead of array form | User input in Open3 methods with shell form |

### §8-2. Indirect Command Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Kernel.open Pipe Injection** | `Kernel.open("| #{user_input}")` or `open("| cmd")` interprets the leading pipe character as a command to execute, not a file to open | User input beginning with `\|` in open() |
| **IO.read/IO.write Pipe Injection** | `IO.read("\| cmd")` and similar IO methods may interpret pipe-prefixed arguments as commands | User input with pipe prefix in IO methods |
| **eval() Code Injection** | `eval(params[:code])` directly executes arbitrary Ruby code | User input in eval() |
| **send/public_send Method Injection** | `object.send(params[:method], params[:arg])` allows invocation of arbitrary methods on any object, potentially reaching dangerous methods | User-controlled method name in send() |
| **constantize/safe_constantize Class Injection** | `params[:class].constantize.new` allows instantiation of arbitrary classes, potentially including those with dangerous constructors or initializers | User input in constantize() |

---

## §9. Rack & Middleware Layer

Rack is the interface layer between Ruby web frameworks and web servers. Rails applications inherit vulnerabilities from Rack and its middleware stack.

### §9-1. Rack-Level Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rack::Static Path Traversal** | Rack::Static concatenates URL paths with the `:root` directory without sanitization. Defaults to `Dir.pwd` if `:root` is unset, exposing project files including configuration and secrets | Rack::Static with default/misconfigured :root (CVE-2025-27610) |
| **CRLF Log Injection** | Rack allows carriage return / line feed characters in log output, enabling injection of fake log entries to hide attacks or create false audit trails | Rack < 2.2.13 / 3.0.14 / 3.1.12 (CVE-2025-25184) |
| **HTTP Header Log Manipulation** | Crafted HTTP headers can manipulate log data through Rack's logging middleware, corrupting audit trails | Rack < patched versions (CVE-2025-27111) |
| **Rack Session Cookie Injection** | Rack's session middleware may accept session cookies from subdomains or different paths, enabling session fixation through subdomain control | Shared domain with attacker-controlled subdomain |
| **Debug Middleware RCE (ShowExceptions)** | `Rack::ShowExceptions` and Sinatra's `ShowExceptions` middleware render interactive debug pages on unhandled exceptions, including an embedded IRB/Pry console that executes arbitrary Ruby code submitted via POST. When debug middleware is accidentally left enabled in production, any request triggering an exception exposes the interactive console, enabling direct RCE without authentication (analogous to Python Werkzeug's debug console) | Debug middleware enabled in production (`Rack::ShowExceptions`, `BetterErrors`, Sinatra `show_exceptions` setting) |

### §9-2. Middleware Ordering Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Auth Middleware Bypass via Ordering** | If authentication middleware is placed after routing or parameter processing middleware, certain requests may reach controllers before authentication is checked | Incorrect middleware stack ordering |
| **CORS Middleware Misconfiguration** | `rack-cors` gem misconfiguration with overly permissive `origins '*'` combined with `credentials: true` enables cross-origin session theft | Wildcard CORS with credentials enabled |

---

## §10. Real-Time Communication (Action Cable)

Action Cable integrates WebSockets into Rails applications. WebSocket connections bypass traditional HTTP security mechanisms (CSRF tokens, same-origin policy enforcement by middleware), creating unique attack surfaces.

### §10-1. WebSocket Security Issues

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | WebSocket upgrade requests include cookies but not CSRF tokens. If `allowed_request_origins` is misconfigured or set to `/.*/`, any origin can establish authenticated WebSocket connections | Permissive allowed_request_origins; cookie-based auth |
| **Base Channel Subscription Bypass** | The restriction on callable action methods in ActionCable is bypassable, allowing subscription to `ActionCable::Channel::Base` directly | Missing channel-level authorization |
| **Slow Client DoS** | ActionCable protects against slow-sending clients but not slow-receiving ones. A client that connects and reads data very slowly ties up Puma worker threads, eventually exhausting the thread pool | Puma server; ActionCable without slow-client protection |
| **Information Exposure via Logs** | ActionCable does not provide a mechanism to filter sensitive data from WebSocket message logs, potentially logging credentials, tokens, or PII in plaintext | ActionCable < 7.1.0; sensitive data in messages |
| **Socket Leak** | ActionCable uses Rack's hijack API to take control of sockets but fails to close them in certain disconnection scenarios, leaking file descriptors and memory | High-connection-churn environments |

---

## §11. Server-Side Request Forgery (SSRF)

Rails applications frequently make outbound HTTP requests for webhooks, URL previews, file fetching, and API integrations. When user input controls the target URL, SSRF enables access to internal services, cloud metadata, and protected resources.

### §11-1. SSRF Vectors in Rails

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **open-uri / URI.open SSRF** | `URI.open(params[:url])` or `open(params[:url])` fetches arbitrary URLs including internal addresses and file:// URIs | User input in URI.open/open URL |
| **Net::HTTP SSRF** | `Net::HTTP.get(URI(params[:url]))` makes requests to user-controlled destinations | User input in Net::HTTP target URL |
| **Active Storage Remote URL** | Active Storage's URL-based attachment mechanism can be abused to fetch from internal services | User-controlled URL in Active Storage attach |
| **Webhook URL SSRF** | Callback/webhook functionality that sends HTTP requests to user-specified URLs | User-configured webhook endpoints |
| **DNS Rebinding TOCTOU** | URL validation resolves the domain to check against blocklists, but the actual HTTP request performs a second resolution. If the DNS record changes between checks (TTL=0), the request reaches an internal IP | Validation-then-request pattern without DNS pinning |
| **IP Representation Bypass** | Internal IP blocklists bypassed via alternative representations: decimal (`2130706433` = `127.0.0.1`), octal (`0177.0.0.01`), hex (`0x7f.0x0.0x0.0x1`), IPv6 (`::1`, `::ffff:127.0.0.1`), or shorthand (`127.1`) | Blocklist-based SSRF protection without normalization |

---

## §12. Native Extension Memory Safety

Ruby's C extensions and built-in methods implemented in C operate outside Ruby's memory-safe runtime, introducing memory corruption and information disclosure risks at the native code level.

### §12-1. Array#pack / String#unpack Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Signedness wrap in pack directives** | `Array#pack` with format directives that specify a length can trigger a signedness wrap when the length value overflows from a large positive integer to a negative value at the C level. The negative length bypasses bounds checking, causing an out-of-bounds read from heap memory — disclosing adjacent heap contents (strings, object references, internal state) in the packed output | User-controlled length or count parameter reaching `Array#pack` format string; Ruby MRI (C implementation) (nastystereo.com "Ruby Array Pack Bleed" research, 2025) |
| **Unpack buffer overread** | `String#unpack` with mismatched format directives reads beyond the source string's allocated buffer, disclosing heap-adjacent memory in the unpacked values | Attacker-controlled format string or length in `unpack`; input string shorter than expected by format |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **RCE via Deserialization** | CookieStore + leaked secret, YAML columns, Active Job, Bootsnap cache | §1-1, §1-2, §1-4, §1-5 |
| **RCE via Command Injection** | File processing, report generation, image transformation | §5-2, §8-1, §8-2 |
| **RCE via Template Injection** | Dynamic template rendering, user-customizable views | §4-1 |
| **Data Exfiltration via SQLi** | ActiveRecord with raw SQL, search functionality | §3-1, §3-2, §3-3 |
| **Data Exfiltration via Path Traversal** | File download, asset serving, template rendering | §4-3, §5-1 |
| **Auth Bypass via Mass Assignment** | User registration, profile update, role management | §2-1, §2-2 |
| **Auth Bypass via Session Manipulation** | Cookie-based sessions, remember-me tokens | §6-1, §6-2 |
| **XSS via Template Bypass** | Rich text editing, user profile rendering, Markdown display | §4-2 |
| **Cache Poisoning** | CDN/proxy caching + Host header manipulation | §7-1 |
| **DoS via ReDoS** | Accept header, email formatting, rich text processing | §7-2 |
| **DoS via WebSocket** | Action Cable with Puma, slow client attacks | §10-1 |
| **SSRF to Cloud Metadata** | Webhook, URL preview, image fetch features | §11-1 |
| **Privilege Escalation via Class Pollution** | Configuration merging, flexible data structures | §2-3 |
| **Heap Information Disclosure** | User-controlled input reaching Array#pack/String#unpack format directives | §12-1 |

---

## CVE / Bounty Mapping (2013–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-2 (YAML Deserialization) | CVE-2013-0156 (Rails XML Parser) | Critical RCE; affected virtually all Rails 2/3 apps. Metasploit module available |
| §1-1 + §1-4 (Marshal + Session Cookie) | CVE-2013-0277 + exploit/multi/http/rails_secret_deserialization | RCE via forged session cookie. Metasploit module |
| §1-2 + §3 (YAML + Serialized Columns) | CVE-2022-32224 (Active Record) | RCE escalation when attacker has SQL injection + YAML-serialized columns |
| §5-2 (Active Storage + MiniMagick) | CVE-2022-21831 (Active Storage) | Code injection via image transformation parameters |
| §5-2 (Active Storage RCE) | CVE-2025-24293 (Active Storage) | RCE via unsafe transformation methods (apply, loader, saver) passed to MiniMagick |
| §4-3 + §5-1 (Render File Traversal) | CVE-2019-5418 (Action View) | Arbitrary file read via Accept header + render file:. CISA KEV listed |
| §1-1 (Active Storage Deserialization) | CVE-2019-5420 (Active Storage) | RCE via Marshal deserialization in Active Storage URL. CVSS 9.8 |
| §4-3 (Render File) + §1-1 (Marshal) | CVE-2019-5418 + CVE-2019-5420 ("DoubleTap") | Chain: file read to extract secret → session cookie forgery → RCE |
| §7-1 (Host Header Open Redirect) | CVE-2021-22881 (Action Pack) | Open redirect via Host Authorization middleware bypass |
| §6-2 (CSRF Bypass) | CVE-2011-0447 (Rails CSRF) | CSRF protection circumvented via plugin/redirect combination |
| §7-2 (Accept Header ReDoS) | CVE-2024-26142 (Action Dispatch) | DoS via catastrophic regex backtracking in Accept parsing |
| §6-2 (Permissions-Policy Gap) | CVE-2024-28103 (Action Pack) | Security header only on HTML responses, leaving APIs unprotected |
| §7-2 (Action Text ReDoS) | CVE-2024-47888 (Action Text) | DoS via crafted blockquote content |
| §5-1 (Rack Path Traversal) | CVE-2025-27610 (Rack::Static) | Arbitrary file read via path traversal. CVSS 7.5 |
| §9-1 (Rack Log Injection) | CVE-2025-25184 (Rack) | CRLF injection in logs enables audit trail manipulation |
| §9-1 (Rack Header Log Manipulation) | CVE-2025-27111 (Rack) | HTTP header-based log data manipulation |
| §4-2 (Sanitizer XSS Bypass) | CVE-2024-53985 (rails-html-sanitizer) | XSS bypass via crafted HTML evading sanitization |
| §4-2 (Sanitizer XSS Bypass) | CVE-2022-23519 (rails-html-sanitizer) | XSS bypass through sanitizer flaw |
| §4-2 (Sanitizer XSS Bypass) | CVE-2022-32209 (rails-html-sanitizer) | XSS via sanitizer allowlist circumvention |
| §5-1 (Sprockets Path Traversal) | CVE-2018-3760 (Sprockets) | Arbitrary file read via asset pipeline traversal |
| §1-1 (Ruby 3.4 Gadget) | Nov 2024 (Ruby 3.4 Universal Gadget) | RCE via new Marshal gadget chain bypassing Ruby 3.2+ patches |
| §1-1 (Gem::SafeMarshal Escape) | Dec 2024 (SafeMarshal Bypass) | Escape from Gem::SafeMarshal protections, subsequently patched |
| §2-2 (_json Parameter Juggling) | _json Juggling Attack (2024) | Authorization bypass via dual interpretation of `_json` parameter in Rails JSON request parsing |
| §1-5 (Bootsnap Cache Poisoning) | Bootsnap Compile Cache RCE (2024) | File write → RCE escalation via Bootsnap compile cache overwrite. Affects Rails ≥ 5.2 with default Bootsnap |
| §12-1 (Array#pack Memory Bleed) | Ruby Array Pack Bleed (nastystereo.com, 2025) | Heap memory disclosure via signedness wrap in Array#pack format directives. Ruby MRI |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Brakeman** (SAST) | Rails application code: SQLi, XSS, CSRF, command injection, mass assignment, deserialization, path traversal | Static analysis of Rails AST; pattern matching against known dangerous method calls and data flows |
| **bundler-audit** (SCA) | Gemfile.lock dependency vulnerabilities | Compares gem versions against ruby-advisory-db database of known CVEs |
| **rails_best_practices** (Linter) | Code quality and security antipatterns | Static analysis for N+1 queries, mass assignment, unused routes, missing indexes |
| **Semgrep** (SAST) | Cross-language static analysis with Ruby/Rails rulesets | Pattern matching with taint tracking; community rules for Rails injection, XSS, deserialization |
| **RuboCop Security** (Linter) | Ruby code security antipatterns | Static cops for eval, send, Marshal.load, YAML.load usage |
| **rails-sqli.org** (Reference) | ActiveRecord SQL injection methods by Rails version | Comprehensive catalog of injectable methods with examples per Rails version |
| **ssrf_filter** (Library) | SSRF prevention in Ruby HTTP calls | Runtime URL validation with DNS pinning, IP blocklist, redirect following |
| **Rack::Attack** (Middleware) | Rate limiting, IP blocking, request throttling | Rack middleware for brute-force and DoS protection |
| **Metasploit** (Exploit Framework) | Rails session deserialization, path traversal, DoS | Exploit modules for CVE-2013-0156, CVE-2019-5418/5420, session cookie forgery |
| **Nuclei** (Scanner) | Rails version detection, known CVE exploitation | YAML-based templates for automated vulnerability scanning |
| **PayloadsAllTheThings** (Reference) | Ruby deserialization payloads, SSTI payloads | Community-maintained payload library for various Ruby/Rails attack vectors |

---

## Summary: Core Principles

### Why Rails Creates This Mutation Space

Ruby on Rails' fundamental design principle — **Convention over Configuration** — is simultaneously its greatest productivity feature and its deepest security liability. The framework provides extensive "magic" (automatic parameter binding, implicit rendering, convention-based routing, serialization helpers) that works beautifully in the happy path but creates opaque attack surfaces when adversarial input is introduced. Developers who rely on Rails' conventions without understanding the underlying mechanisms cannot anticipate how those mechanisms fail under adversarial conditions.

Three architectural properties of the Rails ecosystem make this mutation space particularly large:

1. **Pervasive Serialization**: Marshal and YAML serialization permeate the entire stack — sessions, caches, job queues, database columns, encrypted files. Each serialization point is a potential RCE vector if the signing key is compromised or if the deserialization input can be influenced. Ruby's dynamic object model means deserialization is inherently equivalent to arbitrary code execution, and no amount of "safe loading" can fully prevent gadget chain discovery in a language this reflective.

2. **Implicit Trust in Developer Intent**: Rails assumes developers will use its APIs correctly. Methods like `html_safe`, `raw`, `Arel.sql()`, `permit!`, and `system()` are explicit opt-outs from safety rails — the framework provides them because legitimate use cases exist, but each creates an injection sink when combined with user input. The boundary between "I meant to do that" and "I didn't realize this was dangerous" is the core vulnerability surface.

3. **Deep Framework Integration**: The tight coupling between Rails components creates cross-layer exploit chains that don't exist in loosely-coupled architectures. The classic "DoubleTap" (CVE-2019-5418 + CVE-2019-5420) demonstrates this: a path traversal in Action View extracts the secret key, which enables session cookie forgery through Action Dispatch, which triggers Marshal deserialization for RCE. Each vulnerability alone is limited; combined through Rails' integration points, they achieve full compromise.

### Why Incremental Fixes Fail

Each CVE patch addresses a specific mutation vector, but the underlying architectural patterns remain. Patching `YAML.load` to default to safe mode is defeated by `YAML.unsafe_load`. Patching Marshal gadget chains in Ruby 3.2 is defeated by new gadgets in Ruby 3.4. Restricting Active Storage transformation methods is defeated by the next library that accepts arbitrary options hashes. The mutation space regenerates because it emerges from the intersection of Ruby's dynamic nature, Rails' convention-heavy architecture, and the open-ended semantics of HTTP.

### What Structural Solutions Look Like

True structural mitigation requires moving from opt-in safety to opt-out unsafety at every layer: serialize with JSON by default (not Marshal), parameterize all queries (not just the "safe" methods), sandbox template rendering, validate all file paths against a strict allowlist, and treat every external-facing parameter as adversarial until explicitly validated. Ruby 3.2's `Gem::SafeMarshal` and Rails 7's `raise_on_open_redirects` represent steps in this direction, but the complete transformation requires a cultural shift from "Rails is secure by default" to "Rails provides safety mechanisms that must be consciously applied at every input boundary."

---

## References

- Trail of Bits, "Marshal madness: A brief history of Ruby deserialization exploits," August 2025
- elttam, "Ruby 2.x Universal RCE Deserialization Gadget Chain," November 2018
- GitHub Security Lab / Peter Stöckli, "Ruby Deserialization Exploits," June 2024
- Leonardo Giovannini / Doyensec, "Ruby 3.4 Deserialization Gadget," October 2024
- Alex Leahu / Include Security, "Discovering Deserialization Gadget Chains in Rubyland," March 2024
- Doyensec, "Class Pollution in Ruby: A Deep Dive into Exploiting Recursive Merges," October 2024
- OPSWAT Unit 515, "CVE-2025-24293 Active Storage RCE Discovery," August 2025
- OPSWAT, "Security Analysis of Rack Ruby Framework Vulnerabilities," April 2025
- rails-sqli.org, "Rails SQL Injection Examples" (maintained since 2013)
- Justin Collins / Brakeman, "Rails 6.1 SQL Injection Updates," July 2021
- PortSwigger, "Lab: Exploiting Ruby deserialization using a documented gadget chain"
- Semgrep, "XSS for Ruby on Rails Cheat Sheet"
- OWASP, "Ruby on Rails Cheat Sheet"
- Ruby on Rails Security Guides (official)
- Bishop Fox, "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization"
- TrustedSec, "Ruby ERB Template Injection"
- X41 D-Sec, "Code Audit on Ruby on Rails for the Open Source Technology Improvement Fund"
- Wallarm, "Exploring de-serialization issues in Ruby projects"
- PayloadsAllTheThings, "Insecure Deserialization / Ruby"
- nastystereo, "Rails _json Juggling Attack," 2024
- Convisoappsec, "From Arbitrary File Write to RCE in Restricted Rails Apps," 2024

---

*This document was created for defensive security research and vulnerability understanding purposes.*
