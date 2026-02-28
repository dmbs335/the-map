---
name: study-guide-generator
description: "Generate interactive HTML study guide reports from the-map researcher taxonomy documents (11-researchers/*.md). Produces self-contained, dark-themed HTML files with collapsible technique cards, attack chains, gap analysis tables, timelines, and tool references. Triggered when the user asks to 'create study guide', 'generate study report', 'make HTML report', 'study guide 만들어줘', 'HTML 보고서 생성', or references a researcher profile for report generation."
---

# Study Guide Generator

Generate **self-contained interactive HTML study guide reports** from researcher taxonomy documents in `the-map/11-researchers/`. Each report is a comprehensive, visually polished learning resource with collapsible cards, attack chain visualizations, gap analysis, and timeline.

## Core Principle

> **From Taxonomy to Interactive Learning Resource**
>
> Each researcher's taxonomy document contains structured technique data (tables, sections, examples). This skill transforms that data into a visually rich, interactive HTML report optimized for study and reference. The HTML must be fully self-contained (no external dependencies except fonts) and render correctly when opened directly in a browser.

---

## Workflow Overview

```
1. SOURCE IDENTIFICATION  → Locate researcher taxonomy in 11-researchers/
2. CONTENT EXTRACTION     → Parse sections, tables, techniques, examples
3. CATEGORY MAPPING       → Group techniques into thematic sections
4. GAP ANALYSIS           → Cross-reference with the-map taxonomy docs
5. HTML GENERATION        → Build complete self-contained HTML file
6. DELIVERY               → Save as {researcher}-study-guide.html
```

---

## Phase 1: Source Identification

### Input Patterns

The user may provide:
- **Researcher name**: "Sam Curry study guide 만들어줘" → `11-researchers/sam-curry.md`
- **File path**: "the-map/11-researchers/nagli.md에서 study guide 생성"
- **URL list**: Blog post URLs to analyze (fetch → extract → generate)

### Locate the Taxonomy Document

```
Search: the-map/11-researchers/*.md
Match: researcher name (case-insensitive, hyphenated)
```

If no taxonomy document exists, inform the user and suggest using the `vulnerability-topic-taxonomy-builder` skill first.

---

## Phase 2: Content Extraction

### Parse Taxonomy Structure

Read the researcher's taxonomy document and extract:

```
ResearcherProfile {
  name:           researcher name
  blog_url:       primary blog/site URL
  sections:       list of §N sections with titles
  techniques:     list of all table rows across all sections
  case_studies:   blog posts / CVEs with detailed writeups
  tools:          referenced tools and their usage
  methodology:    core research philosophy / principles
  timeline:       chronological research events
  total_bounty:   documented bounty total (if available)
  collaborators:  research partners
}
```

### Technique Extraction

For each table row in the taxonomy:

```
Technique {
  section:     §N-M reference
  subtype:     technique name (bold text in first column)
  mechanism:   how it works (second column)
  example:     concrete case with code/payload (third column)
  impact:      severity and consequences
  source_post: which blog post / CVE this came from
  tags:        vulnerability category tags for UI display
}
```

### Case Study Extraction

For each blog post or CVE mentioned:

```
CaseStudy {
  title:        blog post title or CVE identifier
  url:          link to source (if available)
  date:         publication date
  target:       organization/product
  bounty:       reward amount (if disclosed)
  techniques:   list of Technique objects used
  attack_chain: ordered steps from entry to impact
  tags:         category tags (auth, ssrf, xss, idor, etc.)
}
```

---

## Phase 3: Category Mapping

Group extracted case studies into thematic sections for the HTML navigation. Choose 6-10 categories based on the researcher's focus areas.

### Default Category Template

Adapt these based on actual content:

```
Possible categories:
- 방법론 (Methodology)
- 인증 및 접근제어 (Auth & Access Control)
- 인젝션 (Injection)
- XSS & SSRF
- 캐시 & 프록시 (Cache & Proxy)
- 인프라 (Infrastructure)
- IoT & 자동차 (IoT & Automotive)
- 메모리 & 암호 (Memory & Crypto)
- API 취약점 (API Vulnerabilities)
- 비즈니스 로직 (Business Logic)
- 레이스 컨디션 (Race Conditions)
- 디시리얼라이제이션 (Deserialization)
- 클라이언트 사이드 (Client-Side)
```

Only include categories that have at least one case study. Merge small categories.

### Tag Color Assignment

Assign tag colors based on vulnerability category:

```
tag-auth:      #1f3a2d / var(--accent2)  — Authentication/Authorization
tag-ssrf:      #2d1f3a / var(--purple)   — SSRF
tag-xss:       #3a1f1f / var(--red)      — XSS
tag-idor:      #3a2d1f / var(--orange)   — IDOR/Access Control
tag-recon:     #1f2d3a / var(--accent)   — Reconnaissance
tag-injection: #3a1f2d / var(--pink)     — Injection
tag-cache:     #2d3a1f / #7ee787         — Cache/Proxy
tag-traversal: #33291a / #d2a641         — Path Traversal
tag-crypto:    #1a2933 / #79c0ff         — Crypto/Session
tag-infra:     #291a33 / #d2a8ff         — Infrastructure
tag-memory:    #33251a / #ffa657         — Memory/Binary
tag-logic:     #1a3329 / #56d364         — Business Logic
tag-race:      #332d1a / #e3b341         — Race Condition
tag-deser:     #331a29 / #ff7b72         — Deserialization
```

---

## Phase 4: Gap Analysis

Cross-reference the researcher's techniques against the-map taxonomy documents.

### Process

1. For each technique in the researcher profile:
   - Search `the-map/` (excluding `11-researchers/`, `skills/`) for the technique
   - Use the gap-analyzer's triple-check methodology
   - Classify as: Covered / Partially Covered / Not Covered

2. Build gap table with:
   - Gap ID (G1, G2, ...)
   - Gap description
   - Source post
   - Target taxonomy file
   - Priority (P1 = new class, P2 = enhancement)

### Gap Table Rules

- Only include genuine gaps (not already in taxonomy)
- Provide specific target file paths
- Prioritize: P1 for entirely new techniques, P2 for enhancements to existing content
- Limit to 20 most significant gaps

---

## Phase 5: HTML Generation

### CRITICAL: Template Structure

The HTML MUST follow this exact structure. Read the reference template file at `skills/study-guide-generator/html-template.md` for the complete CSS and HTML skeleton.

### Document Structure

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css">
  <title>{researcher_name} 연구 - 스터디 가이드</title>
  <style>
    /* Full CSS from template — see html-template.md */
  </style>
</head>
<body>
  <header>...</header>
  <nav>...</nav>
  <!-- Section Groups -->
  <!-- Footer -->
  <script>...</script>
</body>
</html>
```

### Section 1: Header

```html
<header>
  <div class="container">
    <h1>{researcher_name} 연구 스터디 가이드</h1>
    <p class="subtitle">{N}개 블로그 포스트 · 기술 분류 체계 · 공격 체인 분석</p>
    <div class="stats-bar">
      <div class="stat"><div class="stat-num">{post_count}</div><div class="stat-label">블로그 포스트</div></div>
      <div class="stat"><div class="stat-num">{total_bounty}</div><div class="stat-label">총 바운티</div></div>
      <div class="stat"><div class="stat-num">{technique_count}+</div><div class="stat-label">기술</div></div>
      <div class="stat"><div class="stat-num">{year_range}</div><div class="stat-label">기간</div></div>
    </div>
  </div>
</header>
```

### Section 2: Navigation

Sticky navigation bar with links to each section group:

```html
<nav>
  <div class="container">
    <a href="#methodology">방법론</a>
    <a href="#{category_id}">{category_name}</a>
    <!-- ... one per category -->
    <a href="#tools">도구</a>
    <a href="#gaps">갭 분석</a>
  </div>
</nav>
```

### Section 3: Methodology (if available)

Use `principle-card` components for each core principle:

```html
<div class="section-group" id="methodology">
<div class="container">
  <h2>핵심 방법론</h2>
  <p>{researcher_name}의 연구를 관통하는 핵심 원칙.</p>

  <div class="principle-card">
    <h4>"{principle_title}"</h4>
    <p>{principle_description_with_code_examples}</p>
  </div>
  <!-- ... more principles -->
</div>
</div>
```

### Section 4: Category Sections (repeat per category)

Each category contains collapsible cards for case studies:

```html
<div class="section-group" id="{category_id}">
<div class="container">
  <h2>{category_title}</h2>
  <p>{category_description}</p>

  <!-- One card per case study -->
  <div class="card">
    <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
      <div>
        <h3><a href="{post_url}" target="_blank">{case_study_title}</a></h3>
        <div class="card-meta">
          <span class="tag tag-{type}">{tag_label}</span>
          <!-- ... more tags -->
          <span class="date-tag">{date}</span>
        </div>
      </div>
      <span class="bounty">{bounty_amount}</span>
    </div>
    <div class="card-body">
      <!-- Technique blocks -->
      <div class="technique">
        <h4>{technique_name}</h4>
        <p>{mechanism_with_code_highlights}</p>
        <p class="impact">영향: {impact_description}</p>
      </div>
      <!-- ... more techniques -->

      <!-- Attack chain (if multi-step) -->
      <div class="attack-chain">
        <h4>공격 체인</h4>
        <div class="chain-steps">
          <span class="chain-step">{step_1}</span>
          <span class="chain-arrow">&rarr;</span>
          <span class="chain-step">{step_2}</span>
          <!-- ... more steps -->
        </div>
      </div>
    </div>
  </div>
  <!-- ... more cards -->
</div>
</div>
```

### Section 5: Tools Grid

```html
<div class="section-group" id="tools">
<div class="container">
  <h2>참조된 도구 &amp; 기술</h2>
  <div class="tools-grid">
    <div class="tool-card">
      <h4>{tool_name}</h4>
      <p>{tool_description_and_usage}</p>
    </div>
    <!-- ... more tools -->
  </div>
</div>
</div>
```

### Section 6: Gap Analysis Table

```html
<div class="section-group" id="gaps">
<div class="container">
  <h2>the-map 택소노미 대비 갭 분석</h2>
  <p>{N}개 블로그 포스트에서 {M}개의 실행 가능한 갭이 식별됨.</p>

  <table class="gap-table">
    <thead>
      <tr>
        <th>#</th>
        <th>갭</th>
        <th>출처 포스트</th>
        <th>대상 파일</th>
        <th>우선순위</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>G{n}</td>
        <td>{gap_description}</td>
        <td>{source_post}</td>
        <td>{target_file}</td>
        <td class="priority-{1|2}">P{1|2}</td>
      </tr>
      <!-- ... more gaps -->
    </tbody>
  </table>
</div>
</div>
```

### Section 7: Timeline

```html
<div class="section-group">
<div class="container">
  <h2>연구 타임라인</h2>
  <div class="timeline">
    <div class="timeline-item">
      <div class="tl-date">{date}</div>
      <div class="tl-title">{title}</div>
      <div class="tl-detail">{short_description}</div>
    </div>
    <!-- ... sorted newest first -->
  </div>
</div>
</div>
```

### Section 8: Footer

```html
<footer style="text-align: center; padding: 32px 0; color: var(--text-muted); font-size: 0.85em; border-top: 1px solid var(--border);">
  <p><a href="{blog_url}" target="_blank" style="color: var(--accent); text-decoration: none;">{blog_url}</a>에서 수집 &middot; 방어적 보안 연구 및 교육 목적 전용</p>
  <p style="margin-top: 4px;"><strong>the-map</strong> 취약점 택소노미 기준 갭 분석 수행 &middot; {date}</p>
</footer>
```

### Section 9: JavaScript

```html
<script>
// Toggle all cards open/closed with keyboard shortcut
document.addEventListener('keydown', (e) => {
  if (e.key === 'e' && e.altKey) {
    const cards = document.querySelectorAll('.card');
    const allOpen = [...cards].every(c => c.classList.contains('open'));
    cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
  }
});
</script>
```

---

## Content Writing Rules

### Language

- **UI elements**: Korean (section titles, labels, navigation, descriptions)
- **Technical terms**: English (vulnerability names, code, tool names, CVE IDs)
- **Mixed**: Korean sentences with English technical inline terms
- Example: "JWT가 URL 프래그먼트로 추가(<code>#jwt=secret</code>)"

### Technique Descriptions

Each technique block must include:

1. **Mechanism**: HOW it works — specific enough to reproduce
2. **Concrete examples**: Actual payloads, endpoints, parameter names with `<code>` tags
3. **Impact statement**: What an attacker achieves (use `<p class="impact">`)

### Code Highlighting

Use `<code>` tags for:
- URLs and endpoints: `<code>/api/v1/users</code>`
- Payloads: `<code>../../etc/passwd</code>`
- HTTP headers: `<code>X-Original-URL</code>`
- Parameter names: `<code>lpId</code>`
- Tool names in context: `<code>flask-unsign</code>`
- Specific values: `<code>"secret"</code>`

### Attack Chain Rules

- Minimum 3 steps, maximum 8 steps
- Each step should be 2-5 words (concise)
- Show the logical progression from entry to impact
- Use `&rarr;` as arrow between steps

### Bounty Display

- Known amount: `$4,000`, `$40,000`, `$288,500`
- Part of larger amount: `$288,500의 일부`
- Undisclosed: `미공개`
- N/A (CVE): `N/A (CVE)`

---

## Quality Checklist

Before delivering the HTML file:

- [ ] **Self-contained**: Opens correctly in browser with no 404s (only external font CDN)
- [ ] **All sections present**: Header, Nav, Methodology, Categories, Tools, Gaps, Timeline, Footer
- [ ] **Collapsible cards work**: `onclick="this.parentElement.classList.toggle('open')"` on all card headers
- [ ] **Alt+E shortcut works**: Toggles all cards open/closed
- [ ] **Tags are color-coded**: Each tag has appropriate `tag-{type}` class
- [ ] **Attack chains present**: Multi-step cases have visual chain displays
- [ ] **Gap analysis populated**: Cross-referenced with actual the-map taxonomy files
- [ ] **Timeline sorted**: Newest first
- [ ] **Links work**: Blog post URLs are clickable, open in new tab
- [ ] **Responsive**: Renders well on mobile (check @media query)
- [ ] **Korean text**: All UI in Korean, technical terms in English
- [ ] **No placeholder content**: Every field filled with actual data
- [ ] **File saved**: As `{researcher-name}-study-guide.html` in project root

---

## Delivery

### Output File

Save the generated HTML as:
```
{project_root}/{researcher-name}-study-guide.html
```

### Delivery Message

```
# 스터디 가이드 생성 완료

**연구자**: {researcher_name}
**파일**: {researcher-name}-study-guide.html
**블로그 포스트**: {N}개 분석
**기술**: {M}개 추출
**갭**: {K}개 식별

브라우저에서 파일을 열어 확인하세요.
- Alt+E: 모든 카드 접기/펼치기
- 각 카드 헤더 클릭: 개별 접기/펼치기
```

---

## Edge Cases

### No Blog URL Available
- Omit link in card header, use plain text title

### No Bounty Information
- Display `미공개` in bounty field

### Very Large Taxonomy (20+ case studies)
- Group into more categories (up to 10)
- Consider splitting into sub-pages (but keep single-file default)

### Researcher Has No the-map Taxonomy
- If `11-researchers/{name}.md` doesn't exist:
  1. Inform user
  2. Suggest using `vulnerability-topic-taxonomy-builder` to create one first
  3. Or offer to fetch blog posts directly and build from scratch

### Multiple Researchers
- Generate separate HTML files for each
- Do NOT merge into one file

---

*This skill transforms structured taxonomy knowledge into an interactive learning experience. The HTML output is designed for security professionals studying real-world vulnerability research patterns.*
