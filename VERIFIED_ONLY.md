# Source-Dense Review Index

This is a heuristic review index, not a list of fully verified documents. It identifies source-dense files that do not currently contain obvious caveat markers, making them useful candidates for deeper fact-checking.

## Criteria

A document is included when all of the following mechanically testable conditions are true:

- It has no explicit caveat markers such as `unverified`, `verification needed`, `DISPUTED`, `rejected`, `not confirmed`, `no public advisory`, or similar language.
- It has at least 3 external source URLs.
- It is outside `skills/` and `artifact-examples/`.

These conditions measure caveat text and source density only. They do not establish that a source supports the nearby claim, that the source is primary, or that every sentence is correct. Absence of an uncertainty marker is not evidence of verification.

## Source-Dense Working Set

| File | Source URLs | CVE Mentions |
|---|---:|---:|
| `01-injection/css-injection.md` | 44 | 6 |
| `01-injection/el-injection.md` | 23 | 28 |
| `01-injection/latex-injection.md` | 7 | 22 |
| `01-injection/ldap-xpath.md` | 25 | 21 |
| `01-injection/nosql-injection.md` | 20 | 29 |
| `01-injection/sql-injection.md` | 24 | 31 |
| `01-injection/ssi-esi-xslt-injection.md` | 47 | 25 |
| `01-injection/ssti.md` | 21 | 16 |
| `01-injection/xxe.md` | 31 | 15 |
| `02-auth/cors-misconfiguration.md` | 41 | 11 |
| `03-http-protocol/http-header.md` | 20 | 9 |
| `03-http-protocol/http-parsing-discrepancy/protocol-level-waf-bypass.md` | 13 | 15 |
| `03-http-protocol/websocket.md` | 20 | 22 |
| `04-server-side/arbitrary-file-write-to-rce.md` | 20 | 21 |
| `04-server-side/arbitrary-object-instantiation.md` | 15 | 22 |
| `04-server-side/jndi-injection.md` | 21 | 29 |
| `04-server-side/ssrf.md` | 156 | 28 |
| `05-client-side/browser-security-model.md` | 38 | 10 |
| `05-client-side/desktop-hybrid-app-security.md` | 24 | 8 |
| `05-client-side/dom-clobbering.md` | 11 | 16 |
| `05-client-side/open-redirect.md` | 67 | 9 |
| `05-client-side/xs-leak.md` | 28 | 0 |
| `07-application-logic/web-race-condition.md` | 56 | 35 |
| `07-application-logic/web-timing-attack.md` | 15 | 9 |
| `08-infrastructure/api-inventory-management.md` | 12 | 1 |
| `08-infrastructure/container-orchestration-infrastructure-rce.md` | 25 | 48 |
| `08-infrastructure/secondary-context-attack.md` | 24 | 15 |
| `08-infrastructure/waf-bypass.md` | 11 | 1 |
| `09-frameworks-and-languages/django.md` | 18 | 41 |
| `09-frameworks-and-languages/java.md` | 16 | 42 |
| `09-frameworks-and-languages/orm-leak.md` | 21 | 30 |
| `11-researchers/sam-curry.md` | 22 | 2 |
| `11-researchers/soroush-dalili.md` | 17 | 18 |
| `12-product-security/jetty-vulnerability-taxonomy.md` | 14 | 55 |
| `12-product-security/mongodb.md` | 13 | 19 |
| `12-product-security/salesforce-lightning-platform-security.md` | 26 | 11 |
| `12-product-security/wordpress.md` | 43 | 73 |
| `13-misc/dynamic-rendering-engine-exploitation.md` | 28 | 24 |
| `99-deprecated/nat-slipstreaming.md` | 17 | 5 |
| `99-deprecated/rmi.md` | 16 | 12 |

## Excluded By Design

Documents are excluded from this heuristic set when they contain explicit uncertainty markers, disputed/rejected CVE notes, primary-source caveats, or too few external source URLs. Exclusion does not mean a document is wrong, and inclusion does not mean it has been verified.
