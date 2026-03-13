# Web Crawling — Security Reconnaissance Methodology Taxonomy

---

## Classification Structure

This taxonomy structures **crawling techniques for exhaustive attack surface discovery** of web applications. The primary axis is **discovery technique** (§1–§7), with the type of target each technique uncovers as a cross-cutting axis.

| Discovery Target | Description |
|---|---|
| **Paths/Endpoints** | URLs, routes, directories, files |
| **Parameters** | Query, Body, Header, Cookie parameters |
| **API Schema** | Operations, Types, Fields, Mutations |
| **Secrets** | API keys, tokens, credentials, internal URLs |
| **Tech Stack** | Frameworks, versions, middleware, servers |

Fundamental principle of crawling: an application always has **more surface area** than what it intentionally exposes. Deployment artifacts, legacy endpoints, debug interfaces, paths hardcoded in client code — each discovery technique reveals a different region of this hidden surface.

---

## §1. Active Spidering (Link-Based Active Crawling)

The most fundamental crawling approach: visiting pages like a browser, following links, and recursively exploring the application's structure. Modern crawlers (e.g., Burp Suite) go beyond simple link-following — they also submit forms, execute JavaScript, and interact with clickable elements — but discovery scope remains **bounded by reachable application states**.

### §1-1. Traversal Strategy

| Subtype | Mechanism | Use Case |
|---|---|---|
| **Breadth-First** | Visits all links at the same depth before proceeding to the next level. Quickly covers top-level pages and discovers high-importance pages first | Initial surface mapping — rapidly understanding the overall structure of large sites |
| **Depth-First** | Follows a single path to its end before backtracking. Ensures deeply nested functionality (multi-step wizards, nested categories) is not missed | Complete exploration of specific functional areas — payment flows, admin panels, etc. |
| **Hybrid (Adaptive)** | Starts with BFS to grasp the overall structure, then applies DFS to areas of interest | Common default in mature crawlers (e.g., Burp Suite, OWASP ZAP) |

### §1-2. Rendering Mode

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP-Only (Static)** | Parses HTML source only, extracting URLs from `<a>`, `<form>`, `<link>` tags. Fast and lightweight | Server-rendered pages (SSR), legacy applications |
| **Headless Browser (Dynamic)** | Uses Puppeteer, Playwright, etc. to execute JavaScript and collect links generated after DOM mutations. Essential for SPAs | React, Angular, Vue and other client-rendered apps |
| **Hybrid Rendering** | Performs initial crawl with HTTP-Only for speed, switches to headless when JS-dependent paths are detected | Balancing speed and coverage on large sites |

### §1-3. Scope Control

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Same-Origin Restriction** | Only follows links within the same origin (scheme+host+port) | Deep analysis of a single application |
| **Same-Domain Extension** | Crawls including subdomains (`*.example.com`) | Microservice architectures, environments with functionality split across subdomains |
| **Cross-Domain Tracking** | Selectively follows external domain links (CDNs, API servers, auth servers, etc.) | Applications with extensive third-party integrations |
| **URL Normalization & Deduplication** | Removes session IDs, tracking parameters, fragments, etc. to prevent duplicate visits to the same page | Preventing infinite crawl loops — essential for all crawling |
| **Depth/Page Limit** | Sets maximum depth, total page count, per-domain caps | Crawling under resource constraints, large-scale sites |

### §1-4. Form & Interaction Handling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Automatic Form Submission** | Upon discovering `<form>` tags, automatically submits with valid input values and explores the resulting pages | Burp Crawler's form submission feature |
| **Multi-Step Flow Tracking** | Progresses through multi-step flows (wizards, checkouts) sequentially, collecting paths at each stage | Applications with stateful workflows |
| **Event-Driven Discovery** | Triggers DOM events (click, hover, scroll) to discover dynamically generated content | ZAP AJAX Spider, headless-based event crawling |

---

## §2. Directory & File Bruteforcing (Wordlist-Based Path Enumeration)

Discovers hidden paths that have no existing links by guessing them using wordlists. While Active Spidering finds only **what is linked**, bruteforcing finds **what exists but is not linked**.

### §2-1. Basic Bruteforcing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Directory Enumeration** | Tests common path names like `/admin/`, `/backup/`, `/api/v1/` and checks for 200/301/403 responses | General-purpose wordlists (raft-medium, dirb/common.txt) |
| **File Enumeration** | Tests backup/config files: `.bak`, `.old`, `.swp`, `.DS_Store`, `web.config`, `.env` | Extension-specific wordlists, filenames matching the tech stack |
| **Recursive Bruteforcing** | Re-bruteforces inside discovered directories — finding `/api/` → exploring `/api/v1/`, `/api/users/`, `/api/admin/` | feroxbuster, ffuf `-recursion` option |
| **Extension Fuzzing** | Appends various extensions (`.php`, `.asp`, `.jsp`, `.json`, `.xml`) to the same path | When the tech stack is unclear, or multiple technologies coexist |
| **Virtual Host Enumeration** | Tests various hostnames via `Host: FUZZ.example.com` header against the same IP to discover hidden virtual hosts (ffuf, gobuster vhost mode) | Environments where multiple virtual hosts are bound to a single IP — internal admin panels, staging, etc. |

### §2-2. Wordlist Strategy

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **General-Purpose Wordlists** | SecLists, FuzzDB, OneListForAll — common paths regardless of language/framework | Initial exploration, before tech stack identification |
| **Technology-Specific Wordlists** | Framework-specific paths: Spring Boot (`/actuator/*`), WordPress (`/wp-admin/*`), .NET (`/elmah.axd`) | After tech stack identification via Wappalyzer/WhatWeb |
| **Custom Wordlist Generation** | Extracts path conventions from the target site's existing URL patterns to generate tailored lists (CeWL, crawl result analysis) | When the target has unique naming conventions |
| **Assetnote Wordlists** | Wordlists based on real web path frequency extracted from CommonCrawl data | Realistic path names from large-scale crawl data |

### §2-3. Response Analysis & Filtering

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Status Code Filter** | Distinguishes 200 (exists), 301/302 (redirect), 403 (access denied but exists) | Basic filtering — exclude 404s, but custom 404 detection needed |
| **Response Size Filter** | Identifies mass same-size responses as custom 404/error pages and excludes them | ffuf `-fs` (filter size), `-fw` (filter words) |
| **Response Content Filter** | Differentiates real pages from errors by checking for specific strings ("Not Found", "Error") | When custom error pages return 200 responses |
| **Tech Stack-Adaptive Fuzzing** | Automatically selects extensions and wordlists based on technology detected by Wappalyzer (ffufw) | Automated technology-adaptive bruteforcing |

---

## §3. Parameter Discovery (Hidden Parameter Detection)

After finding endpoints — the next step is discovering **hidden parameters** those endpoints process. This includes admin-only parameters removed from client code, debug flags, and undocumented filters.

### §3-1. Parameter Bruteforcing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **GET Parameter Fuzzing** | Tests mass parameters like `?debug=1`, `?admin=true`, `?format=json` and detects response changes | Arjun (25,890 parameters, tested in ~50 requests), x8 (Rust-based, high-speed) |
| **POST Body Fuzzing** | Tests JSON/form body parameters like `{"role":"admin"}`, `{"debug":true}` | Arjun `-m POST`, x8 `-X POST` |
| **HTTP Header Fuzzing** | Tests custom headers like `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` to discover hidden functionality or access control bypasses | param-miner (Burp extension), header-specific wordlists |
| **Cookie Parameter Fuzzing** | Inserts additional parameters into cookie values to check for server-side processing | Applications with cookie-based configuration/feature toggling |

### §3-2. Response Change Detection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Status Code Change** | Response code changes when a specific parameter is added (200→403, 200→500) — indicates the parameter is being processed | The clearest signal |
| **Response Size Change** | Body size changes significantly — additional data returned or error messages altered | Requires baseline response size recording for noise reduction |
| **Response Time Change** | Specific parameter triggers a DB query or external call, increasing response time | Timing-based blind detection |
| **Reflection Detection** | Parameter value is reflected in the response — indicates potential XSS, SSTI, header injection | Tracking where input values are reflected |

### §3-3. Passive Parameter Mining

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Web Archive Parameter Extraction** | ParamSpider — collects past URLs from Wayback Machine for the target domain to extract parameter names | Parameters that existed in the past may still be processed by the server |
| **HTML Source Parameter Extraction** | Collects parameter names from comments, hidden form fields, disabled inputs, data-* attributes | Parameters removed from the client but still processed server-side |
| **JS Source Parameter Extraction** | Analyzes parameters in fetch/XHR calls, JSON keys, and configuration objects within JavaScript code | Links with §4 JavaScript Analysis |

---

## §4. JavaScript Analysis (Client Code Analysis)

The core attack surface of modern web applications is exposed in **JavaScript source code**. API endpoints, auth tokens, internal URLs, routing rules, and debug functionality are bundled and sent to the client.

### §4-1. Endpoint Extraction

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Regex-Based URL Extraction** | LinkFinder — matches URL/path patterns in JS files using regex | Fast but has false positives; suitable for initial scanning |
| **AST-Based Precise Extraction** | jsluice — parses AST via go-tree-sitter, extracting only URLs in actual usage contexts: `fetch()`, `XMLHttpRequest`, `window.open()`, `document.location` | Higher accuracy than regex, reduced false positives |
| **Burp Passive Collection** | JSpector — passively analyzes JS files passing through the proxy, automatically registers discovered endpoints as Burp issues | Automatic JS endpoint detection during live traffic analysis |
| **Bundle Analysis (Source Map)** | If `.js.map` files exist, original source structure can be restored — clearly identifying per-component API calls, route definitions, etc. | When source maps are exposed in production (common) |

### §4-2. Secret Extraction

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **API Keys / Tokens** | SecretFinder — detects API key patterns (`AIza...`, `sk-...`, `ghp_...`), JWTs, Bearer tokens via regex | Authentication info hardcoded in client JS |
| **Internal URLs / Endpoints** | Exposure of non-public URLs: staging servers (`staging.internal.example.com`), internal APIs (`http://10.0.0.x/api`) | Development environment URLs remaining in production builds |
| **Configuration Objects** | Feature flags, environment variables, service URLs exposed in global variables: `window.__CONFIG__`, `window.__INITIAL_STATE__` | SPA initial state delivery pattern |
| **Information in Comments** | Developer comments containing TODOs, FIXMEs, internal notes, references to disabled features | Extracted from pre-minified JS or source maps |

### §4-3. Route & Access Control Analysis

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SPA Route Extraction** | Extracts the full route map from React Router, Vue Router, Angular Router configs — including admin-only paths and hidden pages | Framework-specific router configuration pattern recognition |
| **Role-Based Path Discovery** | Identifies admin-only endpoints/features from client-side access control logic (`if (user.role === 'admin')`) | SPAs with client-side authorization checks |
| **Inactive Feature Detection** | Code paths disabled by feature flags still included in JS — server-side endpoints may remain active | Feature flag-based development, gradual rollouts |

### §4-4. Historical JS Analysis

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Archive JS Comparison** | Collects past versions of JS files from Wayback Machine and diffs against current versions — discovers removed endpoints, changed API paths, deleted secrets | Download past JS files with waymore |
| **Git History JS Analysis** | Tracks JS change history from exposed `.git` directories or GitHub repos — finds API keys and endpoints removed in commits | `.git` directory exposure or source repo access available |

---

## §5. API Surface Discovery (API Schema Enumeration)

Techniques for discovering the full schema of API interfaces including REST, GraphQL, SOAP, and WebSocket. Web UI crawling alone reveals only a portion of the API; schema enumeration uncovers undocumented operations, fields, and types.

### §5-1. REST / OpenAPI Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Swagger/OpenAPI File Search** | Bruteforces known paths: `/swagger.json`, `/openapi.yaml`, `/api-docs`, `/v2/api-docs`, `/swagger-ui.html` | When developers haven't disabled documentation endpoints |
| **API Version Enumeration** | `/api/v1/`, `/api/v2/`, `/api/v3/` — older versions may have more lenient authentication/validation | Environments running multiple API versions in parallel |
| **HTTP Method Fuzzing** | Tests various methods (GET, POST, PUT, DELETE, PATCH, OPTIONS) against the same endpoint to discover undocumented operations | `Allow` header in `OPTIONS` response, or 405 vs 200 response differences |
| **Content-Type Switching** | Sends requests in various formats (`application/json`, `application/xml`, `application/x-www-form-urlencoded`) to the same endpoint — parser differences may expose additional attack surface | When the server accepts multiple Content-Types |

### §5-2. GraphQL Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Introspection Query** | `{__schema{types{name,fields{name}}}}` — bulk extraction of the entire schema (types, fields, mutations, queries) | When introspection is enabled (common even in production) |
| **Introspection Bypass** | GET↔POST method switching, alternative parameter names (`query`, `operationName`), aliased introspection fields, whitespace/encoding tricks | Bypassing naive introspection blocking |
| **Schema Recovery (Clairvoyance)** | When introspection is fully disabled, tools like Clairvoyance exploit field-suggestion error messages (e.g., `Did you mean X?`) to incrementally reconstruct the schema | Hidden endpoint and type discovery without introspection |
| **Field Suggestion-Based Recovery** | When introspection is disabled, sending incorrect field names triggers error messages suggesting similar field names — repeating this reconstructs the schema | InQL, Clairvoyance — error-based schema inference (overlaps with Schema Recovery above) |
| **Endpoint Discovery** | Bruteforcing `/graphql`, `/gql`, `/graphiql`, `/playground`, `/v1/graphql` | When GraphQL endpoint paths are non-standard |

### §5-3. SOAP / WSDL Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WSDL File Search** | Searches `?wsdl`, `?WSDL`, `/service.wsdl`, `/application.wadl` | When SOAP services expose their WSDL |
| **Operation Enumeration** | Extracts operation list from WSDL and individually invokes each operation to test access controls | When WSDL lists all operations but only some require authentication |

### §5-4. WebSocket Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WS Endpoint Discovery** | Discovers `/ws`, `/socket`, `/realtime`, extracts URLs from `new WebSocket()` calls in JS code | Real-time functionality (chat, notifications, dashboards) |
| **Message Format Analysis** | Analyzes the structure of messages transmitted after connection — JSON-RPC, Protocol Buffers, custom protocols | WS traffic capture (Burp WebSocket history) |

---

## §6. Passive & Historical Collection (Non-Contact Collection)

Techniques for collecting attack surface information without sending requests directly to the target server (or with minimal requests). Low direct target visibility (though third-party queries to archives/search engines may still be logged or detected), ability to restore deleted content.

### §6-1. Web Archives

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Wayback Machine URL Collection** | waybackurls, gau, waymore — extracts the complete list of past URLs for the target domain from the Wayback CDX API | Domains with archived capture history |
| **CommonCrawl Data** | Extracts URLs and response data related to the target domain from CommonCrawl indexes | gau includes automatic CommonCrawl search |
| **Past Response Download** | waymore — downloads not just URLs but actual past responses (HTML, JS, JSON) from multiple sources (Wayback, CommonCrawl) to restore deleted content | Verifying deleted pages, removed API responses |
| **Change History Comparison** | Compares temporal snapshots of the same URL to detect added/removed functionality, endpoints, and secrets | Time-series diff analysis |

### §6-2. Search Engines & Indexes

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Google Dorking** | Advanced operators like `site:example.com filetype:pdf`, `site:example.com inurl:admin`, `site:example.com ext:sql` to discover indexed sensitive content | When Google has crawled the content |
| **GitHub/GitLab Search** | `"example.com" password`, `"example.com" api_key` — searching public repos for target-related code, credentials, and internal URLs | Secrets accidentally committed by developers |
| **Shodan / Censys** | IP-based service enumeration — open ports, service banners, SSL certificate info, HTTP response headers | Full picture of internet-exposed services |
| **URLScan.io** | Collects URLs, resources, and redirect chains for the target domain from other users' scan results | When third parties have already scanned the target |

### §6-3. Certificate Transparency

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **crt.sh Subdomain Enumeration** | Queries CT logs for the target domain's SSL certificate history — discovers subdomains, internal hostnames, wildcard patterns | All domains using HTTPS |
| **Internal Hostname Exposure** | Internal subdomains like `staging.internal.example.com`, `jenkins.corp.example.com` included in certificates | When public certificates are issued for internal services |

### §6-4. Metafile Analysis

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **robots.txt** | Extracts the list of paths intended to be hidden from `Disallow` entries — `/admin/`, `/internal/`, `/api/debug/`, etc. | When paths are listed for crawler control purposes, not security |
| **sitemap.xml** | An XML file listing discoverable URLs (subject to 50,000 URL / 50 MB limits per file; sitemap indexes can chain multiple files) — check robots.txt for its referenced location. Coverage is **not guaranteed to be complete** | When the sitemap is publicly accessible |
| **security.txt** | `/.well-known/security.txt` — security contact, policy scope, preferred languages | Bug bounty/VDP program information |
| **humans.txt, crossdomain.xml** | Development team info, Flash/Silverlight cross-domain policies, and other metadata | When legacy configuration files remain |

---

## §7. Authenticated Crawling

Features hidden behind login walls can only be discovered by crawling in an authenticated state. Since the exposed surface varies by privilege level (regular user, admin, API client), **multi-role crawling** is key.

### §7-1. Session Acquisition & Maintenance

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form-Based Login** | Crawler automatically identifies login forms and submits credentials to obtain session cookies | Burp Crawler login configuration, ZAP authentication context |
| **Token-Based Auth** | Injects Bearer tokens, JWTs, or API keys into request headers — API crawling without cookies | Token auto-refresh in ZAP/Burp session handling rules |
| **OAuth Flow Automation** | Completes the OAuth authentication flow via headless browser, extracts the access token for reuse in HTTP clients | OAuth-based authentication (Google, GitHub, etc.) |
| **Cookie Transplant** | Manually logs in via browser, extracts cookies, and injects them into the crawler | When automatic login is difficult due to 2FA, CAPTCHA, etc. |
| **Session Expiry Detection & Re-auth** | Detects session expiry during crawl (302 to login, 401 response) and automatically re-authenticates | Long-running crawls, short session timeouts |

### §7-2. Multi-Role Crawling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unauthenticated → Authenticated Comparison** | Crawls the same endpoint in both unauthenticated and authenticated states, comparing differences — identifies links, features, and parameters visible only after authentication | Foundation data for privilege escalation testing |
| **Per-Role Crawling** | Crawls as each role (regular user, editor, admin) to map role-specific features and endpoints | Burp Crawler's multiple login feature |
| **Authorization Matrix Generation** | Aggregates crawl results across all roles to build an endpoint × role access matrix → basis for IDOR, horizontal/vertical privilege escalation testing | Integration with Autorize (Burp extension), etc. |

### §7-3. Mobile API Crawling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Mobile User-Agent** | Changes crawler's UA to a mobile device to discover mobile-only endpoints, lightweight APIs, and different response formats | Services with separate APIs for mobile apps |
| **App Traffic Capture** | Captures mobile app proxy traffic to collect API endpoints, parameters, and authentication flows | Understanding the API surface without binary analysis |

---

## Crawling Pipeline — Recommended Execution Order

```
Phase 1: Passive Collection (§6)
  ├─ crt.sh subdomain enumeration
  ├─ Wayback/gau URL collection
  ├─ Google Dorking
  ├─ robots.txt / sitemap.xml
  └─ GitHub secret search
      ↓
Phase 2: Active Surface Mapping (§1 + §2)
  ├─ Headless spider (BFS) → overall structure mapping
  ├─ Tech stack identification (Wappalyzer)
  ├─ Technology-specific wordlist directory bruteforcing
  └─ Recursive bruteforcing → deep paths
      ↓
Phase 3: Client Code Analysis (§4)
  ├─ JS file collection (crawl results + archives)
  ├─ jsluice/LinkFinder → endpoint extraction
  ├─ SecretFinder → secret detection
  └─ SPA route analysis
      ↓
Phase 4: API Schema Enumeration (§5)
  ├─ Swagger/OpenAPI search
  ├─ GraphQL introspection / field suggestion
  ├─ HTTP method & Content-Type fuzzing
  └─ WebSocket endpoint analysis
      ↓
Phase 5: Authenticated Deep Crawl (§7)
  ├─ Per-role authenticated crawling
  ├─ Unauthenticated vs authenticated comparison
  ├─ Mobile API crawling
  └─ Authorization matrix generation
      ↓
Phase 6: Parameter Mining (§3)
  ├─ Per-endpoint parameter bruteforcing
  ├─ Archive parameter extraction (ParamSpider)
  └─ Response change analysis
```

---

## Tool Matrix

### Active Crawling (§1)

| Tool | Type | Core Capability |
|---|---|---|
| **Burp Crawler** | Commercial | Integrated crawler with automatic login, form submission, and session handling. Multi-role support |
| **ZAP Spider + AJAX Spider** | Open Source | Traditional crawler + headless browser-based JS rendering crawler |
| **Katana** (ProjectDiscovery) | Open Source | Go-based high-speed crawler. Headless/headful modes, scope control, pipeline integration |
| **GoSpider** | Open Source | Go-based fast crawler. Sitemap parsing, external source integration |
| **hakrawler** | Open Source | Lightweight stdin-based crawler. Optimized for pipeline composition |
| **Crawlee** (Apify) | Open Source | Node.js framework. Selectable Puppeteer/Playwright/Cheerio backends |

### Directory Bruteforcing (§2)

| Tool | Type | Core Capability |
|---|---|---|
| **feroxbuster** | Open Source | Rust-based high-speed recursive content discovery. Auto-filtering, extension fuzzing |
| **ffuf** | Open Source | Go-based general-purpose fuzzer. Directory, parameter, and virtual host fuzzing. Powerful filtering |
| **dirsearch** | Open Source | Python-based. Extension combination, recursive discovery, diverse wordlist support |
| **gobuster** | Open Source | Go-based lightweight. Directory, DNS, and virtual host modes |

### Parameter Discovery (§3)

| Tool | Type | Core Capability |
|---|---|---|
| **Arjun** | Open Source | 25,890 parameter dictionary, tested in ~50 requests. GET/POST/JSON support |
| **x8** | Open Source | Rust-based high-speed. Custom wordlists, header/cookie parameter support |
| **param-miner** | Open Source (Burp) | Burp extension. Automatic detection of headers, cookies, and URL parameters |
| **ParamSpider** | Open Source | Past parameter extraction from Wayback. Passive source-based |

### JavaScript Analysis (§4)

| Tool | Type | Core Capability |
|---|---|---|
| **jsluice** (BishopFox) | Open Source | AST-based precise URL/secret extraction. go-tree-sitter powered |
| **LinkFinder** | Open Source | Regex-based JS endpoint extraction. HTML report generation |
| **SecretFinder** | Open Source | API key, token, and credential pattern matching in JS |
| **JSpector** | Open Source (Burp) | Burp extension. Automatic analysis of JS files passing through proxy, auto issue registration |

### API Discovery (§5)

| Tool | Type | Core Capability |
|---|---|---|
| **InQL** | Open Source (Burp) | GraphQL introspection, field suggestion-based schema recovery, query generation |
| **Clairvoyance** | Open Source | Error feedback-based GraphQL schema reconstruction when introspection is disabled |
| **sj** (Swagger Jacker) | Open Source | Endpoint extraction and authentication test automation from Swagger/OpenAPI files |
| **Postman/Hoppscotch** | Open Source | Manual API exploration and testing after importing OpenAPI/GraphQL schemas |

### Passive Collection (§6)

| Tool | Type | Core Capability |
|---|---|---|
| **gau** | Open Source | Bulk URL collection from Wayback, CommonCrawl, URLScan, and VirusTotal |
| **waymore** (xnl-h4ck3r) | Open Source | Downloads URLs + past responses from multiple sources (Wayback, CommonCrawl, URLScan). Enhanced filtering options |
| **waybackurls** | Open Source | Fast URL extraction from Wayback Machine only |
| **crt.sh** | Web Service | Certificate Transparency log-based subdomain enumeration |

---

## Core Principles

**1. Never rely on a single technique.** Active Spidering finds only linked content, Bruteforcing finds only guessable paths, and JS Analysis finds only information included in client code. Each technique covers a different area, and maximum coverage comes from the **union of all techniques**.

**2. Start passive.** Before sending a single request to the target, first secure all information collectible from archives and public sources. This allows mapping a significant portion of the attack surface without detection, and guides the direction of subsequent active crawling.

**3. Adapt to the tech stack.** Use `/actuator/*` wordlists for Spring Boot apps, introspection for GraphQL services, and headless rendering for SPAs. General-purpose crawling is the baseline, but **technology-specific crawling reveals unique surface area.**

**4. Leverage the time axis.** Analyze not just the current live state, but also past states (Wayback), source history (Git), and API version history. Removed endpoints and secrets may still be functional on the server.

**5. Switch roles.** The same application exposes different attack surfaces from the perspectives of unauthenticated users, regular users, admins, API clients, and mobile apps. Multi-role crawling provides the foundation data for IDOR and privilege escalation vulnerabilities.

---

## References

- OWASP. "Web Security Testing Guide — Information Gathering." OWASP WSTG Latest.
- OWASP. "API Reconnaissance." OWASP WSTG Latest.
- YesWeHack. "Discover & Map Hidden Endpoints & Parameters." YesWeHack Learn.
- YesWeHack. "Parameter Discovery Quick Guide." YesWeHack Learn.
- YesWeHack. "Harnessing Wayback Machine for Bug Bounty." YesWeHack Learn.
- Intigriti. "7 Overlooked Recon Techniques to Find More Vulnerabilities." Intigriti Blog.
- Intigriti. "Finding Hidden Input Parameters: Advanced Enumeration Guide." Intigriti Blog.
- PortSwigger. "Crawling — Burp Suite Documentation." PortSwigger Docs.
- PortSwigger. "Crawling with Multiple Logins." PortSwigger Blog.
- PortSwigger. "API Testing." Web Security Academy.
- ProjectDiscovery. "Building a Fast One-Shot Recon Script." ProjectDiscovery Blog.
- BishopFox. "jsluice: Extract URLs, paths, secrets from JavaScript." GitHub.
- HackTricks. "Web API Pentesting." HackTricks Wiki.
- HackTricks. "GraphQL." HackTricks Wiki.
- kpwn.de. "JavaScript Analysis for Pentesters." 2023.
- SwissKyRepo. "PayloadsAllTheThings — Hidden Parameters." GitHub.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
