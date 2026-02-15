---
name: burp-extension-generator
description: "Generate Burp Suite extensions from the-map vulnerability taxonomy documents. This skill reads taxonomy files from the-map knowledge base and generates fully-functional Burp Suite extensions (Java/Kotlin) with scanner checks, passive/active tests, and UI components. Triggered when the user asks to 'create Burp extension', 'generate Burp plugin', 'make Burp scanner check', or references specific vulnerability classes from the-map for tooling generation. Implements clean architecture with separated concerns: detection logic, HTTP handling, UI, and configuration."
---

# Burp Suite Extension Generator

Generate **production-ready Burp Suite extensions** from the-map vulnerability taxonomy documents. The extension includes scanner checks, HTTP message processors, and UI components based on mutation taxonomy.

## Core Principle

> **From Taxonomy to Detection Logic**
>
> Every mutation variant in the taxonomy becomes a concrete test case in the Burp extension. The three-axis structure (Mutation Target, Discrepancy Type, Attack Scenario) directly maps to extension architecture: what to mutate, how to detect discrepancies, and where to report findings.

---

## Workflow Overview

```
1. TARGET SELECTION    → Identify which the-map document to convert
2. TAXONOMY ANALYSIS   → Parse the mutation axes and subtypes
3. ARCHITECTURE DESIGN → Design extension structure (checks, processors, UI)
4. CODE GENERATION     → Generate Java/Kotlin code with clean architecture
5. TESTING STRATEGY    → Generate test cases and validation code
6. DELIVERY            → Package extension with build files and README
```

---

## Phase 1: Target Selection

### Input Patterns

The user may request:
- "Create a Burp extension for XSS detection based on the-map"
- "Generate Burp scanner checks for HTTP Request Smuggling"
- "Make a Burp plugin for JWT vulnerabilities from the taxonomy"
- "Convert the SSRF taxonomy to a Burp extension"

### Target Identification

1. **Identify the taxonomy document**: Match user request to the-map file
   ```
   User: "Burp extension for JWT" → the-map/02-auth/jwt/jwt.md
   User: "HTTP smuggling scanner" → the-map/03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md
   ```

2. **Read the taxonomy document**: Use Read tool to load the full content
   ```
   Read the taxonomy file completely to understand:
   - Classification axes
   - Mutation categories
   - Subtypes and mechanisms
   - Detection conditions
   ```

3. **Scope confirmation**: Confirm with user if needed
   ```
   If the taxonomy is very large (50+ subtypes), ask:
   "This taxonomy contains X mutation variants. Should I:
    - Generate comprehensive extension (all variants)
    - Focus on specific categories (which ones?)
    - Split into multiple extensions (active/passive/modules)"
   ```

---

## Phase 2: Taxonomy Analysis

### Axis Extraction

Parse the taxonomy structure to extract:

```markdown
## Axis 1: Mutation Targets (Primary Structure)
§1. [Category 1] → Scanner check module 1
§2. [Category 2] → Scanner check module 2
...

## Axis 2: Discrepancy Types (Detection Logic)
- Encoding differential → String comparison checks
- Parser differential → Response diff analysis
- WAF evasion → Baseline + bypass payload comparison
- CSP bypass → Header parsing + policy evaluation

## Axis 3: Attack Scenarios (Severity & Context)
- RCE → Critical severity
- Auth bypass → High severity
- Information disclosure → Medium severity
```

### Subtype Mapping

For each subtype in the taxonomy, extract:

```
Subtype: [Name from table]
Mechanism: [How it works — detection strategy]
Example Payload: [Concrete test string]
Key Condition: [When to test — request filtering]
Detection Method: [Response pattern / error / behavior]
```

**Example from XSS taxonomy**:
```
Subtype: Event Handler Element Injection - Auto-firing events
Mechanism: <img src=x onerror=alert(1)> fires automatically
Example Payload: <img src=x onerror=alert(document.domain)>
Key Condition: Reflection in HTML context, < > not filtered
Detection: Alert execution or onerror in response
```

---

## Phase 3: Architecture Design

### Extension Structure (Clean Architecture)

```
burp-[vulnerability]-extension/
├── src/main/
│   ├── java/com/themap/burp/[vuln]/
│   │   ├── Extension.java              # Burp API entry point
│   │   ├── scanner/
│   │   │   ├── ScannerCheck.java       # Implements IScannerCheck
│   │   │   ├── PassiveCheck.java       # Passive scanning
│   │   │   ├── ActiveCheck.java        # Active scanning
│   │   │   └── checks/                 # Individual check implementations
│   │   │       ├── Category1Check.java # Maps to §1 in taxonomy
│   │   │       ├── Category2Check.java # Maps to §2
│   │   │       └── ...
│   │   ├── detector/
│   │   │   ├── PayloadGenerator.java   # Generate test payloads
│   │   │   ├── ResponseAnalyzer.java   # Analyze responses
│   │   │   └── ContextDetector.java    # Detect injection context
│   │   ├── model/
│   │   │   ├── MutationVariant.java    # Data model for mutations
│   │   │   ├── ScanResult.java         # Scan finding model
│   │   │   └── VulnerabilityContext.java
│   │   ├── ui/
│   │   │   ├── ConfigPanel.java        # Extension settings UI
│   │   │   └── ResultsPanel.java       # Custom results view
│   │   └── util/
│   │       ├── HttpHelper.java         # HTTP message utilities
│   │       └── PayloadEncoder.java     # Encoding utilities
│   └── resources/
│       ├── payloads/                    # Payload wordlists
│       └── config/                      # Default configurations
├── build.gradle                         # Gradle build file
├── README.md                            # Extension documentation
└── examples/                            # Example vulnerable apps
```

### Component Responsibilities

#### 1. Scanner Check (IScannerCheck implementation)

```java
// Maps taxonomy categories to scanner logic
class [Category]Check implements IScannerCheck {
    // Passive: analyze existing traffic
    List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)

    // Active: inject test payloads
    List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
                                   IScannerInsertionPoint insertionPoint)
}
```

**Mapping rule**:
- Each top-level category (§1, §2, etc.) → one Check class
- Each subtype → one test method within the Check class
- Passive checks: response pattern matching (no mutation)
- Active checks: payload injection + response validation

#### 2. Payload Generator

```java
class PayloadGenerator {
    // Generate payloads for each mutation subtype
    List<Payload> generatePayloads(MutationCategory category,
                                   InjectionContext context)

    // Encoding variations (Axis 2: Defense Bypass)
    List<Payload> applyEncodingVariations(Payload base)
}
```

**Mapping rule**:
- Each subtype's "Example" column → base payload
- Axis 2 (Discrepancy/Bypass) → payload transformation functions
- Context-aware generation based on injection point type

#### 3. Response Analyzer

```java
class ResponseAnalyzer {
    // Detect successful exploitation
    ScanResult analyzeResponse(IHttpRequestResponse response,
                               Payload payload,
                               DetectionStrategy strategy)

    // Different detection strategies per subtype
    boolean detectByPattern(String response, Pattern pattern)
    boolean detectByBehavior(IHttpRequestResponse response)
    boolean detectByDiff(IHttpRequestResponse baseline,
                        IHttpRequestResponse test)
}
```

**Mapping rule**:
- "Key Condition" column → filter for when to test
- "Mechanism" column → detection logic
- Response patterns extracted from taxonomy examples

---

## Phase 4: Code Generation

### Code Generation Rules

#### Rule 1: Clean Architecture Separation

```
NEVER: Put detection logic in Extension.java
NEVER: Mix UI code with scanner logic
NEVER: Hard-code payloads in check classes

ALWAYS: Separate concerns into dedicated packages
ALWAYS: Use dependency injection where possible
ALWAYS: Load payloads from external resources
ALWAYS: Make checks independently testable
```

#### Rule 2: Burp API Best Practices

```java
// Use IExtensionHelpers for all HTTP manipulation
IExtensionHelpers helpers = callbacks.getHelpers();
byte[] request = helpers.buildHttpRequest(url);

// Thread-safe access to Burp state
synchronized(this) {
    // Access shared state
}

// Proper issue reporting
return Arrays.asList(new CustomScanIssue(
    baseRequestResponse.getHttpService(),
    helpers.analyzeRequest(baseRequestResponse).getUrl(),
    new IHttpRequestResponse[] { attackRequestResponse },
    "Issue Title",
    "Issue Detail",
    "High",
    "Certain"
));
```

#### Rule 3: Taxonomy Metadata in Code

```java
/**
 * Implements: XSS Taxonomy §1-2 "Event Handler Element Injection"
 * Mutation Target: HTML Element Context
 * Discrepancy Type: Parser Differential (sanitizer bypass)
 * References: the-map/01-injection/xss/xss.md
 */
class EventHandlerInjectionCheck implements IScannerCheck {
    // Implementation
}
```

Every check class includes taxonomy reference in Javadoc.

#### Rule 4: Configurable Aggressiveness

```java
enum ScanLevel {
    LIGHT,      // Top 10 most common payloads
    NORMAL,     // All documented subtypes
    THOROUGH,   // All subtypes + encoding variations
    EXHAUSTIVE  // All combinations (Axis1 × Axis2)
}
```

UI provides scan level selector based on taxonomy coverage.

### Generated File Templates

#### Extension.java (Entry Point)

```java
package com.themap.burp.[vuln];

import burp.*;
import com.themap.burp.[vuln].scanner.*;
import com.themap.burp.[vuln].ui.*;

public class Extension implements IBurpExtender, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("[Vulnerability] Scanner - The Map");

        // Register scanner checks
        callbacks.registerScannerCheck(new PassiveCheck(callbacks));
        callbacks.registerScannerCheck(new ActiveCheck(callbacks));

        // Register UI
        callbacks.addSuiteTab(new ConfigPanel(callbacks));

        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        // Cleanup
    }
}
```

#### ScannerCheck Template (Per Category)

```java
package com.themap.burp.[vuln].scanner.checks;

import burp.*;
import com.themap.burp.[vuln].detector.*;
import com.themap.burp.[vuln].model.*;
import java.util.*;

/**
 * Taxonomy: [Vulnerability] §[N]. [Category Name]
 * Mutation Target: [Target description]
 * Source: the-map/[path]/[file].md
 */
public class [Category]Check implements IScannerCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PayloadGenerator payloadGen;
    private final ResponseAnalyzer analyzer;

    public [Category]Check(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.payloadGen = new PayloadGenerator();
        this.analyzer = new ResponseAnalyzer(helpers);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // Passive detection for this category
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doActiveScan(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        // Get base response for comparison
        byte[] baseResponse = baseRequestResponse.getResponse();

        // Test each subtype
        issues.addAll(testSubtype1(baseRequestResponse, insertionPoint, baseResponse));
        issues.addAll(testSubtype2(baseRequestResponse, insertionPoint, baseResponse));
        // ... for each subtype in §[N]

        return issues;
    }

    /**
     * §[N]-[M]. [Subtype Name]
     * Mechanism: [Description from taxonomy]
     */
    private List<IScanIssue> testSubtype1(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint,
            byte[] baseResponse) {

        List<IScanIssue> issues = new ArrayList<>();

        // Generate payloads for this subtype
        List<Payload> payloads = payloadGen.generateFor("[Subtype]");

        for (Payload payload : payloads) {
            // Build attack request
            byte[] checkRequest = insertionPoint.buildRequest(
                payload.getBytes()
            );

            // Send request
            IHttpRequestResponse checkRequestResponse =
                callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    checkRequest
                );

            // Analyze response
            ScanResult result = analyzer.analyze(
                checkRequestResponse,
                payload,
                DetectionStrategy.PATTERN_MATCH
            );

            if (result.isVulnerable()) {
                issues.add(createIssue(
                    baseRequestResponse,
                    checkRequestResponse,
                    result
                ));
            }
        }

        return issues;
    }

    private IScanIssue createIssue(
            IHttpRequestResponse baseRequestResponse,
            IHttpRequestResponse attackRequestResponse,
            ScanResult result) {

        return new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[] { attackRequestResponse },
            "[Vulnerability]: [Subtype Name]",
            generateIssueDetail(result),
            "High",  // Severity from Axis 3 mapping
            "Firm"   // Confidence
        );
    }

    private String generateIssueDetail(ScanResult result) {
        return String.format(
            "<p><b>Taxonomy Reference:</b> the-map/[path] §[N]-[M]</p>" +
            "<p><b>Mutation Target:</b> [Target]</p>" +
            "<p><b>Mechanism:</b> [Mechanism from taxonomy]</p>" +
            "<p><b>Payload Used:</b> <code>%s</code></p>" +
            "<p><b>Detection:</b> %s</p>",
            result.getPayload(),
            result.getDetectionEvidence()
        );
    }

    @Override
    public int consolidateDuplicateIssues(
            IScanIssue existingIssue,
            IScanIssue newIssue) {
        // Same URL + same issue name = duplicate
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;  // Keep existing
        }
        return 0;  // Keep both
    }
}
```

#### PayloadGenerator.java

```java
package com.themap.burp.[vuln].detector;

import com.themap.burp.[vuln].model.*;
import java.util.*;

/**
 * Generates test payloads from taxonomy mutation variants
 */
public class PayloadGenerator {

    // Payloads organized by taxonomy category
    private Map<String, List<Payload>> payloadDatabase;

    public PayloadGenerator() {
        this.payloadDatabase = new HashMap<>();
        loadPayloads();
    }

    /**
     * Load payloads from taxonomy subtypes
     * Each subtype's "Example" column becomes a payload
     */
    private void loadPayloads() {
        // §1 payloads
        payloadDatabase.put("category1-subtype1", Arrays.asList(
            new Payload("[payload from taxonomy]", "[context]"),
            // ... more payloads
        ));

        // ... for all subtypes
    }

    public List<Payload> generateFor(String subtypeName) {
        List<Payload> base = payloadDatabase.get(subtypeName);
        if (base == null) return Collections.emptyList();

        // Apply encoding variations (Axis 2: Defense Bypass)
        List<Payload> variations = new ArrayList<>(base);
        for (Payload p : base) {
            variations.addAll(applyEncodingVariations(p));
        }

        return variations;
    }

    /**
     * Apply Axis 2 bypass techniques: encoding differentials,
     * parser differentials, WAF evasion, etc.
     */
    private List<Payload> applyEncodingVariations(Payload base) {
        List<Payload> variations = new ArrayList<>();

        // URL encoding
        variations.add(base.urlEncode());

        // Double encoding
        variations.add(base.urlEncode().urlEncode());

        // HTML entities (for XSS)
        variations.add(base.htmlEntityEncode());

        // Case variation
        variations.add(base.caseVariation());

        // ... more transformations from Axis 2

        return variations;
    }
}
```

#### ResponseAnalyzer.java

```java
package com.themap.burp.[vuln].detector;

import burp.*;
import com.themap.burp.[vuln].model.*;
import java.util.regex.*;

public class ResponseAnalyzer {

    private final IExtensionHelpers helpers;

    public ResponseAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    public ScanResult analyze(
            IHttpRequestResponse response,
            Payload payload,
            DetectionStrategy strategy) {

        switch (strategy) {
            case PATTERN_MATCH:
                return detectByPattern(response, payload);
            case BEHAVIOR:
                return detectByBehavior(response, payload);
            case DIFF:
                return detectByDiff(response, payload);
            default:
                return ScanResult.notVulnerable();
        }
    }

    private ScanResult detectByPattern(
            IHttpRequestResponse response,
            Payload payload) {

        String responseBody = helpers.bytesToString(response.getResponse());

        // Check if payload is reflected
        if (responseBody.contains(payload.getValue())) {
            return ScanResult.vulnerable(
                payload,
                "Payload reflected in response",
                responseBody
            );
        }

        return ScanResult.notVulnerable();
    }

    private ScanResult detectByBehavior(
            IHttpRequestResponse response,
            Payload payload) {

        // Check for behavioral indicators
        // e.g., error messages, timing differences, etc.

        IResponseInfo responseInfo = helpers.analyzeResponse(
            response.getResponse()
        );

        short statusCode = responseInfo.getStatusCode();

        // Taxonomy-specific detection logic
        // ...

        return ScanResult.notVulnerable();
    }

    private ScanResult detectByDiff(
            IHttpRequestResponse response,
            Payload payload) {

        // Compare with baseline response
        // Used for blind vulnerabilities

        return ScanResult.notVulnerable();
    }
}
```

#### Build Configuration (build.gradle)

```gradle
plugins {
    id 'java'
}

group = 'com.themap.burp'
version = '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    // Burp Extender API
    compileOnly files('lib/burp-extender-api.jar')

    // Testing
    testImplementation 'junit:junit:4.13.2'
    testImplementation 'org.mockito:mockito-core:4.11.0'
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

jar {
    manifest {
        attributes 'Implementation-Title': '[Vulnerability] Scanner - The Map'
        attributes 'Implementation-Version': version
    }

    // Create fat JAR with dependencies
    from {
        configurations.runtimeClasspath.collect {
            it.isDirectory() ? it : zipTree(it)
        }
    }

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
```

#### README.md Template

```markdown
# [Vulnerability] Scanner - The Map

Burp Suite extension for detecting [vulnerability] vulnerabilities based on
[the-map](https://github.com/...) mutation taxonomy.

## Features

- **Comprehensive Coverage**: Implements [X] mutation variants from the taxonomy
- **Passive & Active Scanning**: Both traffic analysis and active testing
- **Taxonomy-Based**: Each check directly maps to taxonomy categories
- **Configurable**: Scan level from light to exhaustive
- **Clean Architecture**: Modular, testable, maintainable code

## Installation

1. Download `burp-[vuln]-extension.jar` from releases
2. In Burp Suite: Extender → Extensions → Add
3. Select the JAR file
4. Extension loads automatically

## Taxonomy Coverage

This extension implements:

### §1. [Category 1 Name]
- [x] §1-1. [Subtype]
- [x] §1-2. [Subtype]
- ...

### §2. [Category 2 Name]
- [x] §2-1. [Subtype]
- ...

[Continue for all categories]

## Usage

### Passive Scanning
The extension automatically analyzes all HTTP traffic passing through Burp
for [vulnerability] patterns.

### Active Scanning
1. Right-click on request → "Actively scan this host"
2. Or use Scanner tool with this extension enabled
3. Configure scan level in extension settings

### Configuration
Extension tab provides:
- Scan level selection (Light/Normal/Thorough/Exhaustive)
- Enable/disable specific check categories
- Custom payload configuration
- Results filtering

## Detection Methods

The extension uses multiple detection strategies from the taxonomy:

- **Pattern Matching**: Payload reflection analysis
- **Behavioral**: Error messages, status codes, timing
- **Differential**: Compare baseline vs attack responses
- **Context-Aware**: Detect injection context before testing

## Taxonomy Reference

Source taxonomy: `the-map/[path]/[file].md`

Each scanner issue includes:
- Taxonomy section reference (§N-M)
- Mutation target description
- Mechanism explanation
- Payload used
- Detection evidence

## Building from Source

```bash
git clone https://github.com/...
cd burp-[vuln]-extension
./gradlew build
# Output: build/libs/burp-[vuln]-extension.jar
```

## Testing

```bash
./gradlew test
```

Includes unit tests for:
- Payload generation
- Response analysis
- Detection logic
- Each subtype check

## Architecture

```
Extension.java          → Burp API entry point
scanner/
  ├── PassiveCheck      → Passive scanning
  ├── ActiveCheck       → Active scanning coordinator
  └── checks/           → Per-category check implementations
detector/
  ├── PayloadGenerator  → Mutation variant payloads
  ├── ResponseAnalyzer  → Detection logic
  └── ContextDetector   → Injection context identification
model/
  ├── Payload           → Payload data model
  └── ScanResult        → Finding data model
ui/
  └── ConfigPanel       → Extension configuration UI
```

## License

MIT License - see LICENSE file

## Credits

Based on [the-map](https://github.com/...) vulnerability taxonomy by [author].

## Contributing

Contributions welcome! Please:
1. Reference specific taxonomy sections in issues/PRs
2. Add tests for new checks
3. Update README with new coverage
```

---

## Phase 5: Testing Strategy

### Test Generation

For each check class, generate unit tests:

```java
package com.themap.burp.[vuln].scanner.checks;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class [Category]CheckTest {

    private [Category]Check check;
    private IBurpExtenderCallbacks mockCallbacks;
    private IExtensionHelpers mockHelpers;

    @Before
    public void setUp() {
        mockCallbacks = mock(IBurpExtenderCallbacks.class);
        mockHelpers = mock(IExtensionHelpers.class);
        when(mockCallbacks.getHelpers()).thenReturn(mockHelpers);

        check = new [Category]Check(mockCallbacks);
    }

    /**
     * Test §[N]-[M]: [Subtype Name]
     */
    @Test
    public void testSubtype1Detection() {
        // Arrange
        IHttpRequestResponse mockReq = createMockRequest(
            "[test payload from taxonomy]"
        );
        IScannerInsertionPoint mockInsertionPoint =
            createMockInsertionPoint();

        // Act
        List<IScanIssue> issues = check.doActiveScan(
            mockReq,
            mockInsertionPoint
        );

        // Assert
        assertEquals(1, issues.size());
        assertEquals(
            "[Vulnerability]: [Subtype Name]",
            issues.get(0).getIssueName()
        );
    }

    @Test
    public void testNoFalsePositive() {
        // Test with clean response
        // Assert no issues reported
    }
}
```

### Manual Testing Guide

Generate testing guide with vulnerable examples:

```markdown
# Manual Testing Guide

## Test Case 1: §1-1 [Subtype]

**Vulnerable Example**:
```
[Code snippet showing vulnerable application]
```

**Steps**:
1. Navigate to [URL]
2. Enable extension
3. Submit [payload]
4. Verify issue detected

**Expected Result**:
- Scanner issue created
- Severity: [High/Medium/Low]
- Detail includes taxonomy reference
```

---

## Phase 6: Delivery

### Packaging

Create complete project structure:

```
burp-[vuln]-extension/
├── src/
├── lib/
│   └── burp-extender-api.jar
├── build.gradle
├── README.md
├── LICENSE
├── TESTING.md
└── examples/
    └── vulnerable-app/
```

### Output Location

Save to: `c:\Users\dmbs3\Downloads\the-map\outputs\burp-[vuln]-extension\`

Create within the-map project's outputs directory for easy access.

### Delivery Message Template

```markdown
# Burp Suite Extension Generated

I've created a complete Burp Suite extension for [Vulnerability] detection
based on the-map taxonomy.

## Summary

- **Taxonomy Source**: [the-map/path/file.md]
- **Coverage**: [X] mutation variants across [Y] categories
- **Check Types**: [N] passive checks, [M] active checks
- **Code Size**: ~[XXX] lines
- **Architecture**: Clean separation (scanner/detector/model/ui)

## Files Generated

1. **Extension Code**: Full Java implementation
2. **Build System**: Gradle configuration
3. **Tests**: Unit tests for all checks
4. **Documentation**: README + manual testing guide
5. **Examples**: Vulnerable test applications

## Quick Start

```bash
cd burp-[vuln]-extension
./gradlew build
# Load build/libs/burp-[vuln]-extension.jar in Burp Suite
```

## Taxonomy Mapping

Each scanner check directly implements taxonomy sections:

| Taxonomy Section | Check Class | Subtypes |
|-----------------|-------------|----------|
| §1. [Category]  | [Category]Check.java | [N] variants |
| §2. [Category]  | [Category]Check.java | [M] variants |
...

## Next Steps

1. Review generated code
2. Build extension: `./gradlew build`
3. Load in Burp Suite
4. Test against examples in `examples/` directory
5. Customize payload configurations in `src/main/resources/payloads/`

The extension is production-ready and follows Burp Suite best practices.
All detection logic is backed by the taxonomy's mutation variants.
```

---

## Configuration Options

### Scan Aggressiveness Levels

```
LIGHT (default):
- Top 10 most common subtypes per category
- Minimal encoding variations
- Fast scanning

NORMAL:
- All documented subtypes
- Standard encoding variations
- Balanced speed/coverage

THOROUGH:
- All subtypes + all encoding variations (Axis 2)
- Extended detection timeouts
- Comprehensive coverage

EXHAUSTIVE:
- All subtypes × all bypass techniques
- Combinatorial explosion of Axis1 × Axis2
- Very slow, maximum coverage
```

### Category Toggles

Allow users to enable/disable specific categories:

```
[x] §1. [Category 1]
[x] §2. [Category 2]
[ ] §3. [Category 3] (disabled for speed)
...
```

---

## Quality Checklist

Before delivery, verify:

- [ ] **All taxonomy subtypes have corresponding check methods**
- [ ] **Each check class has Javadoc with taxonomy reference**
- [ ] **Payload examples from taxonomy are used**
- [ ] **Detection logic matches "Key Condition" from taxonomy**
- [ ] **Scanner issues include taxonomy section reference**
- [ ] **Build succeeds with no errors: `./gradlew build`**
- [ ] **Tests pass: `./gradlew test`**
- [ ] **README documents all implemented categories**
- [ ] **Extension loads in Burp without errors**
- [ ] **Manual test cases included for each category**

---

## Advanced Features (Optional)

### Differential Testing

For subtle vulnerabilities, implement baseline comparison:

```java
// Store baseline response
byte[] baseline = getCleanResponse(insertionPoint);

// Test with payload
byte[] testResponse = getResponseWithPayload(insertionPoint, payload);

// Compare
if (hasMeaningfulDifference(baseline, testResponse)) {
    // Vulnerable
}
```

### Context Detection

Before testing, detect injection context:

```java
enum InjectionContext {
    HTML_ELEMENT,    // Test §1 payloads
    HTML_ATTRIBUTE,  // Test §2 payloads
    JAVASCRIPT,      // Test §3 payloads
    URL,             // Test §4 payloads
    UNKNOWN          // Test all
}

InjectionContext ctx = detectContext(insertionPoint);
List<Payload> payloads = payloadGen.generateFor(subtype, ctx);
```

### Collaborative Scanning

Support for Burp Collaborator:

```java
// For blind vulnerabilities (SSRF, XXE, etc.)
IBurpCollaboratorClientContext collab =
    callbacks.createBurpCollaboratorClientContext();

String collabDomain = collab.generatePayload(true);
String payload = String.format("[payload with %s]", collabDomain);

// ... send payload ...

// Check for interactions
List<IBurpCollaboratorInteraction> interactions =
    collab.fetchCollaboratorInteractionsFor(collabDomain);

if (!interactions.isEmpty()) {
    // Blind vulnerability confirmed
}
```

---

## Iteration Support

After initial delivery, support:

- **"Add category §N"**: Generate check class for additional category
- **"Optimize for speed"**: Reduce payload count, prioritize fast checks
- **"Add blind detection"**: Integrate Burp Collaborator
- **"Convert to Kotlin"**: Rewrite in Kotlin with same architecture
- **"Add custom payloads"**: Provide UI for user payload addition

For all iterations: maintain architecture, update README, regenerate tests.

---

## Example Generation Workflow

```
User: "Create a Burp extension for JWT attacks from the-map"

1. Read: the-map/02-auth/jwt/jwt.md
2. Parse taxonomy axes:
   - Axis 1: Algorithm, Claims, Signature, Headers, etc.
   - Axis 2: Algorithm confusion, Key injection, Claim abuse, etc.
   - Axis 3: Auth bypass, Privilege escalation, Information disclosure
3. Generate architecture:
   - AlgorithmConfusionCheck.java (§1)
   - ClaimAbuseCheck.java (§2)
   - SignatureBypassCheck.java (§3)
   - ...
4. Implement checks with payloads from taxonomy
5. Generate tests
6. Package and deliver

Output: burp-jwt-extension/ with full codebase
```

---

## Notes

- **Language**: Generate all code in English (comments, variable names, docs)
- **Code Style**: Follow Google Java Style Guide
- **Burp API**: Use latest Burp Extender API conventions
- **Dependencies**: Minimize external dependencies (Burp API only)
- **Licensing**: MIT license, attribute the-map taxonomy
- **Maintainability**: Prioritize readability over cleverness
