# The-Map Coverage Map

Quick reference for the gap-analyzer skill. Maps each taxonomy file to its coverage area, key terms, and section count.

**Last updated:** 2025-02

---

## 01-injection/ (14 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `sql-injection.md` | SQL injection: WHERE clause, UNION, error-based, blind, OOB, stacked, WAF bypass, full-text search, PDO | SQLi, SQL injection, UNION, boolean blind, time-based, prepared statement |
| `nosql-injection.md` | NoSQL: MongoDB, CouchDB, Redis, Elasticsearch, Neo4j, DynamoDB operator injection | NoSQL, MongoDB, $ne, $gt, $regex, operator injection |
| `command-injection.md` | OS command injection: separators, whitespace evasion, shell expansion, argument injection | command injection, RCE, shell, backtick, semicolon, pipe |
| `xss.md` | XSS: HTML/attribute/JS/URL/CSS context, DOM sinks, mXSS, CSP bypass, sanitizer bypass, CSTI, framework-specific | XSS, cross-site scripting, innerHTML, DOM, CSP, sanitizer, DOMPurify, AngularJS |
| `ssti.md` | SSTI: Jinja2, Twig, FreeMarker, Velocity, Thymeleaf, Pebble, Smarty, ERB, Razor, EJS, sandbox escape | SSTI, template injection, Jinja2, Twig, FreeMarker, sandbox escape |
| `el-injection.md` | Expression Language: SpEL, JSP EL, OGNL, MVEL | SpEL, OGNL, expression language, EL injection |
| `xxe.md` | XXE: general/parameter entities, DTD, protocol handlers, encoding, parser-specific, Billion Laughs | XXE, XML, external entity, DTD, libxml2, ENTITY |
| `ldap-xpath.md` | LDAP and XPath injection | LDAP injection, XPath, LDAP filter |
| `prototype-pollution.md` | Prototype pollution: recursive merge, query string, constructor, DOM gadgets, RCE chains | prototype pollution, __proto__, constructor, merge, gadget |
| `graphql.md` | GraphQL: introspection, batching, resolver injection, authz bypass, subscription abuse | GraphQL, introspection, mutation, subscription, batching |
| `latex-injection.md` | LaTeX injection: \write18, file I/O, LuaTeX/XeTeX | LaTeX, \write18, LuaTeX |
| `protocol-level-injection.md` | Protocol injection: Redis, Memcached, FastCGI, FTP, LDAP wire protocol | Redis, Memcached, FastCGI, CRLF, protocol injection |
| `ssi-esi-xslt-injection.md` | SSI, ESI, XSLT injection | SSI, ESI, XSLT, Edge Side Include |
| `orm-misuse-sql-injection.md` | ORM misuse → SQLi: Django, SQLAlchemy, ActiveRecord, Hibernate, Sequelize, Prisma | ORM, Django ORM, ActiveRecord, Hibernate, raw query |

## 02-auth/ (11 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `jwt.md` | JWT: alg:none, RS→HS confusion, kid injection, jku/jwk/x5u/x5c, weak secrets, claim tampering | JWT, JSON Web Token, alg:none, kid, jku, HMAC |
| `oauth.md` | OAuth 2.0/OIDC: redirect_uri, code interception, token leakage, PKCE, mix-up, state/CSRF | OAuth, OIDC, redirect_uri, authorization code, PKCE, token |
| `saml.md` | SAML: XSW, signature validation, canonicalization, parser differential, Golden SAML | SAML, XSW, signature wrapping, canonicalization, XML signature |
| `csrf.md` | CSRF: token bypass, SameSite, Content-Type, Origin/Referer, WebSocket CSRF | CSRF, SameSite, cross-site request forgery, Origin header |
| `cookie.md` | Cookie: SameSite bypass, cookie tossing, cookie sandwich, prefix bypass | cookie, SameSite, HttpOnly, cookie tossing, __Host- |
| `cors-misconfiguration.md` | CORS: origin validation, null origin, wildcard, preflight bypass | CORS, Access-Control, origin, preflight, cross-origin |
| `idor-bola.md` | IDOR/BOLA: sequential ID, UUID, cross-method, nested resource | IDOR, BOLA, insecure direct object reference |
| `account-takeover.md` | Account takeover: pre-registration, OAuth linking, password reset, token prediction | account takeover, password reset, token, pre-registration |
| `authentication-bypass-and-sso.md` | Auth bypass: Kerberos, NTLM, FIDO2/WebAuthn, MFA bypass, middleware bypass | authentication bypass, MFA, WebAuthn, FIDO2, SSO |
| `mass-assignment.md` | Mass assignment: role injection, Spring @ModelAttribute, Rails strong_params | mass assignment, data binding, parameter binding |
| `cryptographic-implementation-vulnerabilities.md` | Crypto: cipher modes, RSA, ECDSA, hash, TLS, RNG, side-channel, AEAD/GCM | cryptographic, AES, RSA, ECDSA, GCM, nonce, padding oracle |

## 03-http-protocol/ (9 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `http-parsing-discrepancy/http-request-smuggling.md` | Smuggling: CL.TE, TE.CL, CL.0, H2 desync, chunk encoding, TLS desync, Opossum | smuggling, desync, CL.TE, TE.CL, Content-Length, Transfer-Encoding |
| `http-header.md` | Header injection: Host, X-Forwarded-For, X-Original-URL, CRLF | Host header, CRLF, X-Forwarded-For, header injection |
| `http-parameter-pollution.md` | HPP: first/last wins, delimiter, array notation | parameter pollution, HPP, duplicate parameter |
| `websocket.md` | WebSocket: CSWSH, origin bypass, message injection, proxy confusion | WebSocket, CSWSH, handshake, ws://, wss:// |
| `grpc-and-trpc.md` | gRPC/tRPC: H2 rapid reset, Protobuf confusion, metadata manipulation | gRPC, tRPC, Protobuf, HTTP/2, rapid reset |
| `dns-web-security.md` | DNS: cache poisoning, rebinding, subdomain takeover, DoH/DoT | DNS, rebinding, subdomain takeover, TOCTOU |
| `http-parsing-discrepancy/reverse-proxy-misrouting.md` | Reverse proxy: path normalization, dot-segment, percent-encoding | reverse proxy, path normalization, nginx, Apache, routing |
| `http-parsing-discrepancy/protocol-level-waf-bypass.md` | Protocol-level WAF bypass: smuggling, method/header manipulation, content-type | WAF bypass, protocol, HTTP/2, content-type |
| `http-parsing-discrepancy/http-censorship-bypass.md` | Censorship bypass: TCP fragmentation, TLS/SNI, QUIC, DNS circumvention | censorship, SNI, TLS, fragmentation, QUIC |

## 04-server-side/ (14 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `ssrf.md` | SSRF: IP bypass, DNS rebinding, URL parser, protocol scheme, cloud metadata, blind | SSRF, server-side request forgery, metadata, 169.254 |
| `path-traversal.md` | Path traversal: encoding, platform separators, normalization, null byte, symlink | path traversal, ../, directory traversal, LFI |
| `file-upload.md` | File upload: extension, Content-Type, magic bytes, .htaccess, race conditions | file upload, extension bypass, webshell |
| `deserialization.md` | Deserialization: Java gadgets, Python pickle, PHP unserialize, .NET, Ruby Marshal | deserialization, gadget chain, pickle, unserialize |
| `jndi-injection.md` | JNDI: RMI/LDAP class loading, Log4Shell, post-patch gadgets | JNDI, Log4Shell, RMI, LDAP, remote class |
| `rmi.md` | Java RMI: registry deserialization, DGC, JEP 290 | RMI, registry, DGC, JEP 290 |
| `jdbc-attack.md` | JDBC: MySQL LOAD DATA, H2 script exec, PostgreSQL class instantiation | JDBC, MySQL, H2, PostgreSQL, connection string |
| `jaas-attack.md` | JAAS: LoginModule, JNDI class loading, Kafka/ZooKeeper | JAAS, LoginModule, Kafka, ZooKeeper |
| `jmx-attack.md` | JMX: MBean registration, Jolokia, deserialization | JMX, MBean, Jolokia, JConsole |
| `document-media-processing-library-rce.md` | Doc/media RCE: ImageMagick, Ghostscript, LibreOffice, FFmpeg, PDF.js, ExifTool | ImageMagick, Ghostscript, FFmpeg, ExifTool, PDF |
| `email-smuggling-and-parser-abuse.md` | Email: SMTP injection, MIME, DKIM/DMARC/SPF, header injection | email, SMTP, MIME, DKIM, DMARC, SPF |
| `file-download.md` | File download: IDOR, access control, Content-Disposition, pre-signed URL | file download, Content-Disposition, pre-signed URL |
| `arbitrary-file-write-to-rce.md` | AFW→RCE: webshell, config overwrite, cron, SSH keys, .pyc/.so/.pth | arbitrary file write, webshell, .htaccess, cron, .pyc |
| `http-pipelining-attack.md` | HTTP pipelining: response queue poisoning, response smuggling | pipelining, response queue, response smuggling |

## 05-client-side/ (9 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `xs-leak.md` | XS-Leaks: timing, error/success, frame counting, cache oracle, CSS exfil, connection pool | XS-Leak, timing, side-channel, cache oracle, connection pool |
| `dom-clobbering.md` | DOM clobbering: named property, window/document shadowing, library gadgets, DOMPurify | DOM clobbering, named property, id, name, document.currentScript |
| `ui-redressing.md` | Clickjacking: iframe overlay, cursor spoofing, SVG filters, drag-drop, extension DOM | clickjacking, UI redressing, iframe, overlay, SVG filter |
| `open-redirect.md` | Open redirect: allowlist bypass, parser differential, scheme bypass | open redirect, redirect, javascript:, data: |
| `browser-security-model.md` | Browser security: SOP, CSP bypass, cookie security, frame protection, HSTS, COOP/COEP | SOP, CSP, same-origin, nonce, Content-Security-Policy |
| `browser-extension-security.md` | Extension security: permission bypass, content script, postMessage, supply chain | extension, chrome.runtime, content script, manifest |
| `service-worker.md` | Service Worker: registration, importScripts, cache poisoning, persistent XSS | service worker, importScripts, Cache API, SW |
| `client-side-web-security.md` | Client-side: storage, cross-origin communication, frame/window, timing | localStorage, postMessage, window.open, iframe |
| `desktop-hybrid-app-security.md` | Electron/Tauri: renderer→main escalation, context isolation, sandbox escape | Electron, Tauri, nodeIntegration, contextIsolation, IPC |

## 06-encoding-parser/ (4 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `url-confusion.md` | URL confusion: scheme, authority, path normalization, query/fragment, Unicode | URL parsing, WHATWG, RFC 3986, scheme, authority |
| `unicode.md` | Unicode: encoding mismatch, normalization, case mapping, homoglyph, invisible chars | Unicode, UTF-8, normalization, NFC, NFKC, homoglyph |
| `type-confusion-and-coercion.md` | Type confusion: PHP loose comparison, JS coercion, JIT, Protobuf, JSON precision, Go | type confusion, loose comparison, coercion, JIT, float64 |
| `zip-archive.md` | ZIP/archive: Zip Slip, parser differential, Zip Bomb, polyglot, MOTW | ZIP, archive, Zip Slip, decompression bomb |

## 07-application-logic/ (7 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `business-logic-bug.md` | Business logic: price manipulation, workflow bypass, coupon abuse, feature flag | business logic, price, workflow, coupon, rate limit |
| `state-machine-violation.md` | State machine: transition bypass, guard bypass, TOCTOU, protocol confusion | state machine, transition, guard, FSM |
| `web-race-condition.md` | Race conditions: TOCTOU, double-spend, single-packet, HTTP/2, HTTP/3 QUIC | race condition, TOCTOU, single-packet, double-spend |
| `web-timing-attack.md` | Timing attacks: sequential, concurrent, timeless, event-based, AbortController | timing attack, timeless timing, timing oracle |
| `implicit-trust-boundary.md` | Trust boundaries: internal network, proxy headers, microservice lateral movement | trust boundary, X-Forwarded-For, internal, microservice |
| `numeric-and-boundary-logic.md` | Numeric: integer overflow, signed/unsigned, floating-point, NaN, scientific notation | integer overflow, signed, unsigned, NaN, Infinity |
| `secondary-context-attack.md` | Secondary context: path normalization differential, parser differential, API gateway | secondary context, BFF, API gateway, path normalization |

## 08-infrastructure/ (7 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `dependency-confusion.md` | Dependency confusion: namespace squatting, manifest leakage, slopsquatting | dependency confusion, npm, PyPI, supply chain |
| `web-cache-poisoning-and-deception.md` | Cache poisoning/deception: unkeyed header, URL delimiter, fat GET, WCD | cache poisoning, cache deception, unkeyed, CDN |
| `waf-bypass.md` | Payload WAF bypass: encoding, SQL alternatives, JS obfuscation, ReDoS against WAF | WAF bypass, encoding, obfuscation, regex |
| `ci-cd-pipeline-security.md` | CI/CD: YAML injection, PPE, runner compromise, secret exposure, AI agent injection | CI/CD, GitHub Actions, pipeline, runner, secret |
| `api-inventory-management.md` | API inventory: shadow API, zombie API, drift, discovery methods | shadow API, zombie API, API inventory |
| `container-orchestration-infrastructure-rce.md` | Container: runtime escape, eBPF, cgroup, K8s RBAC, admission webhook | container, Docker, Kubernetes, escape, eBPF |
| `developer-toolchain-build-system-rce.md` | Toolchain: build system, compiler plugin, IDE extension, LSP, pre-commit | build system, compiler, IDE, LSP, pre-commit |

## 09-frameworks-and-languages/ (8 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `modern-js-frameworks.md` | Next.js, React, Vue, Nuxt, Angular, Svelte, Remix, Astro: middleware bypass, RSC, cache poisoning | Next.js, React, Vue, Nuxt, Angular, Svelte, Astro |
| `spring.md` | Spring: SpEL, Actuator, Spring4Shell, mass assignment, Cloud Function | Spring, SpEL, Actuator, @ModelAttribute |
| `asp-dot-net.md` | ASP.NET: ViewState, path normalization, Razor, SignalR, Blazor, IIS, SOAPwn | ASP.NET, ViewState, Razor, IIS, SignalR, SOAP |
| `php.md` | PHP: loose comparison, unserialize, stream wrappers, disable_functions | PHP, unserialize, php://, phar://, type juggling |
| `ruby-on-rails.md` | Rails: mass assignment, ERB/Haml, ActiveRecord, YAML deserialization, Array#pack | Rails, ActiveRecord, ERB, strong_params, Marshal |
| `orm-leak.md` | ORM Leak: filter injection, relationship traversal, Beego, Prisma, ordering | ORM leak, filter, Beego, Prisma, ordering |

## 10-recon-methodology/ (4 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `recon.md` | Hidden parameter discovery: static analysis, dynamic probing, traffic archaeology | parameter discovery, hidden parameter, source map |
| `web-fingerprinting.md` | Fingerprinting: server banner, error page, HTTP behavior, TLS (JA3/JA4) | fingerprint, banner, JA3, JA4, server detection |
| `web-fuzzing.md` | Fuzzing: path discovery, parameter fuzzing, grammar-based, coverage-guided, LLM-assisted | fuzzing, ffuf, wfuzz, coverage-guided, mutation |
| `ctf-exotic-tricks.md` | CTF: sandbox escape, crypto misuse, non-HTTP parsers, constrained exploitation | CTF, sandbox escape, jail, constrained |

## 12-product-security/ (7 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `sap.md` | SAP: RFC, Diag, ICM, ABAP, HANA, Fiori, NetWeaver | SAP, ABAP, HANA, Fiori, NetWeaver, RFC |
| `aem.md` | AEM: Dispatcher, Sling, selectors, OSGi, CRXDE | AEM, Adobe Experience Manager, Sling, Dispatcher |
| `salesforce-lightning-platform-security.md` | Salesforce: SOQL, Apex, LWC/Aura, CRUD/FLS, guest user, AgentForce | Salesforce, SOQL, Apex, Lightning, LWC |
| `sharepoint-vulnerability-taxonomy.md` | SharePoint: deserialization, auth bypass, web shells, machine keys | SharePoint, ViewState, Machine Key, TypeConverter |
| `wordpress.md` | WordPress: plugin exploitation, REST API, XML-RPC, PHP object injection | WordPress, WP, plugin, wp-admin, xmlrpc |
| `nginx-vulnerability-taxonomy.md` | Nginx: alias traversal, off-by-slash, merge_slashes, proxy_pass | Nginx, alias, off-by-slash, proxy_pass |
| `jetty-vulnerability-taxonomy.md` | Jetty: ambiguous path, servlet mapping, HTTP/2, WEB-INF | Jetty, servlet, WEB-INF, ambiguous path |

## 13-misc/ (2 files)

| File | Coverage | Key Search Terms |
|------|----------|-----------------|
| `ai-llm-security.md` | AI/LLM: prompt injection, jailbreak, training data, agent exploitation, MCP | LLM, prompt injection, jailbreak, AI agent, MCP |
| `web-application-dos.md` | App-layer DoS: ReDoS, hash collision, nested parsing, Slowloris, amplification | DoS, ReDoS, Slowloris, hash collision, amplification |
