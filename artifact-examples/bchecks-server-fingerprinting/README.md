# BChecks - Server-Side Web Fingerprinting (The Map)

Burp Suite BChecks for server-side web fingerprinting and technology stack detection based on the-map taxonomy (§5 Server-Side Fingerprinting, §6 Web Application Technology Fingerprinting).

## Summary

- **28 BCheck files** covering server-side fingerprinting
- **Passive checks**: 17 (analyze existing traffic, zero additional requests)
- **Active checks**: 11 (send probe requests)
- **Taxonomy coverage**: §5-1 through §5-4, §6-1 through §6-3

## Installation

1. Burp Suite Professional -> Extensions -> BChecks
2. Import -> Select .bcheck files from `bchecks/` directory
3. All checks activate automatically during scanning

## BChecks Coverage

### §5. Server-Side Fingerprinting

| File | Type | Description | Taxonomy |
|------|------|-------------|----------|
| `s5-1-server-banner-extraction.bcheck` | Passive | Server header software detection | §5-1 |
| `s5-1-server-version-disclosure.bcheck` | Passive | Exact version number in Server header | §5-1 |
| `s5-1-x-powered-by-disclosure.bcheck` | Passive | X-Powered-By technology leak | §5-1 |
| `s5-1-aspnet-version-header.bcheck` | Passive | X-AspNet-Version / X-AspNetMvc-Version | §5-1 |
| `s5-1-header-value-formatting.bcheck` | Passive | ETag format, X-Request-Id pattern analysis | §5-1 |
| `s5-2-error-page-fingerprinting.bcheck` | Active | Default 404 page signatures (Apache, nginx, IIS, Tomcat, Spring, Django, Flask, Laravel) | §5-2 |
| `s5-2-status-code-differential.bcheck` | Active | Long URL and invalid method response analysis | §5-2 |
| `s5-3-http-method-profiling.bcheck` | Active | TRACE/OPTIONS method support detection | §5-3 |
| `s5-3-url-normalization-probe.bcheck` | Active | Path traversal, backslash, double-slash handling | §5-3 |
| `s5-3-connection-behavior.bcheck` | Passive | Keep-Alive, X-Runtime, X-Response-Time analysis | §5-3 |
| `s5-4-cdn-identification.bcheck` | Passive | CDN detection (Cloudflare, CloudFront, Akamai, Fastly, Vercel, Netlify) | §5-4 |
| `s5-4-multi-layer-detection.bcheck` | Passive | Multi-layer architecture identification | §5-4 |

### §6. Web Application Technology Fingerprinting

| File | Type | Description | Taxonomy |
|------|------|-------------|----------|
| `s6-1-framework-header-markers.bcheck` | Passive | Drupal, WordPress, Magento, Shopify headers | §6-1 |
| `s6-1-php-version-disclosure.bcheck` | Passive | PHP version via X-Powered-By | §6-1 |
| `s6-1-java-server-detection.bcheck` | Passive | Tomcat, Jetty, WildFly, WebLogic, GlassFish | §6-1 |
| `s6-1-python-framework-detection.bcheck` | Passive | Django, Flask, FastAPI, Tornado | §6-1 |
| `s6-1-nodejs-framework-detection.bcheck` | Passive | Express, Next.js, Nuxt.js | §6-1 |
| `s6-1-cookie-framework-fingerprint.bcheck` | Passive | PHPSESSID, JSESSIONID, laravel_session, _rails_session, connect.sid, etc. | §6-1 |
| `s6-1-js-framework-detection.bcheck` | Passive | React, Angular, Vue, Svelte DOM patterns | §6-1 |
| `s6-1-security-header-absence.bcheck` | Passive | Missing security headers as deployment maturity indicator | §6-1 |
| `s6-1-wordpress-detection.bcheck` | Active | wp-login.php, readme.html, user enumeration | §6-1 |
| `s6-1-cms-path-detection.bcheck` | Active | Joomla, Drupal, Laravel .env, Next.js paths | §6-1 |
| `s6-2-debug-endpoint-exposure.bcheck` | Active | Actuator, phpinfo, ELMAH, GraphQL introspection | §6-2 |
| `s6-2-api-docs-exposure.bcheck` | Active | Swagger UI, OpenAPI, FastAPI /docs | §6-2 |
| `s6-2-source-map-exposure.bcheck` | Passive | SourceMap header, sourceMappingURL comments | §6-2 |
| `s6-2-version-leak-passive.bcheck` | Passive | HTML generator meta tag, version comments, "Powered by" | §6-2 |
| `s6-2-rss-sitemap-version.bcheck` | Active | robots.txt, RSS feed generator tags | §6-2 |
| `s6-3-waf-detection.bcheck` | Active | WAF identification (Cloudflare, Akamai, ModSecurity, Imperva, AWS WAF) | §6-3 |

## Detection Technology Coverage

### Server Software
Apache, nginx, IIS, Tomcat, Jetty, WildFly, WebLogic, GlassFish, Kestrel, LiteSpeed, Caddy, Gunicorn, uWSGI, uvicorn

### Frameworks / CMS
WordPress, Drupal, Joomla, Magento, Shopify, Laravel, Rails, Django, Flask, FastAPI, Express, Next.js, Nuxt.js, Spring Boot, ASP.NET, NestJS, Angular, React, Vue, Svelte

### CDN / WAF
Cloudflare, CloudFront, Akamai, Fastly, Varnish, Vercel, Netlify, ModSecurity, NAXSI, Imperva, AWS WAF

## Taxonomy Source

`the-map/10-recon-methodology/web-fingerprinting/web-fingerprinting.md`
