# HTML Template Reference

This file contains the complete CSS and HTML skeleton for the study guide generator. The generated HTML must include ALL of this CSS verbatim (with only variable values changed).

## Complete CSS

```css
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #1c2333;
  --border: #30363d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --accent2: #3fb950;
  --red: #f85149;
  --orange: #d29922;
  --purple: #bc8cff;
  --pink: #f778ba;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Pretendard', 'Noto Sans KR', -apple-system, BlinkMacSystemFont, 'Malgun Gothic', sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.8;
  word-break: keep-all;
  letter-spacing: -0.01em;
}
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

/* Header */
header {
  background: linear-gradient(135deg, #0d1117 0%, #1a1e2e 50%, #161b22 100%);
  border-bottom: 1px solid var(--border);
  padding: 48px 0;
  text-align: center;
}
header h1 {
  font-size: 2.2em;
  font-weight: 800;
  background: linear-gradient(90deg, var(--accent), var(--purple));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 12px;
  letter-spacing: -0.03em;
}
header .subtitle {
  color: var(--text-muted);
  font-size: 1.1em;
  margin-bottom: 24px;
}
.stats-bar {
  display: flex;
  justify-content: center;
  gap: 32px;
  flex-wrap: wrap;
}
.stat { text-align: center; }
.stat-num {
  font-size: 2em;
  font-weight: 700;
  color: var(--accent);
}
.stat-label {
  font-size: 0.82em;
  color: var(--text-muted);
  letter-spacing: 0.5px;
}

/* Navigation */
nav {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 0;
  position: sticky;
  top: 0;
  z-index: 100;
}
nav .container {
  display: flex;
  gap: 8px;
  overflow-x: auto;
  padding-bottom: 4px;
}
nav a {
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.83em;
  font-weight: 500;
  padding: 6px 14px;
  border-radius: 6px;
  white-space: nowrap;
  transition: all 0.2s;
}
nav a:hover {
  background: var(--surface2);
  color: var(--text);
}

/* Sections */
.section-group {
  padding: 48px 0;
  border-bottom: 1px solid var(--border);
}
.section-group h2 {
  font-size: 1.5em;
  font-weight: 700;
  margin-bottom: 10px;
  color: var(--accent);
  letter-spacing: -0.02em;
}
.section-group > p {
  color: var(--text-muted);
  margin-bottom: 32px;
  max-width: 720px;
  line-height: 1.7;
}

/* Cards */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 24px;
  overflow: hidden;
  transition: border-color 0.2s;
}
.card:hover { border-color: var(--accent); }
.card-header {
  padding: 20px 24px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  cursor: pointer;
  user-select: none;
}
.card-header h3 {
  font-size: 1.1em;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.card-header h3 a {
  color: var(--text);
  text-decoration: none;
}
.card-header h3 a:hover { color: var(--accent); }
.card-meta {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 6px;
}
.tag {
  font-size: 0.73em;
  padding: 3px 9px;
  border-radius: 12px;
  font-weight: 600;
  letter-spacing: 0;
}
.tag-auth { background: #1f3a2d; color: var(--accent2); }
.tag-ssrf { background: #2d1f3a; color: var(--purple); }
.tag-xss { background: #3a1f1f; color: var(--red); }
.tag-idor { background: #3a2d1f; color: var(--orange); }
.tag-recon { background: #1f2d3a; color: var(--accent); }
.tag-injection { background: #3a1f2d; color: var(--pink); }
.tag-cache { background: #2d3a1f; color: #7ee787; }
.tag-traversal { background: #33291a; color: #d2a641; }
.tag-crypto { background: #1a2933; color: #79c0ff; }
.tag-infra { background: #291a33; color: #d2a8ff; }
.tag-memory { background: #33251a; color: #ffa657; }
.tag-logic { background: #1a3329; color: #56d364; }
.tag-race { background: #332d1a; color: #e3b341; }
.tag-deser { background: #331a29; color: #ff7b72; }
.bounty {
  color: var(--accent2);
  font-weight: 700;
  font-size: 0.9em;
  white-space: nowrap;
}
.date-tag {
  color: var(--text-muted);
  font-size: 0.8em;
  white-space: nowrap;
}

.card-body {
  padding: 0 24px 24px;
  display: none;
}
.card.open .card-body { display: block; }
.card-header::after {
  content: '\25BC';
  color: var(--text-muted);
  font-size: 0.7em;
  transition: transform 0.2s;
  flex-shrink: 0;
  margin-top: 4px;
}
.card.open .card-header::after { transform: rotate(180deg); }

/* Technique list */
.technique {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 12px;
}
.technique h4 {
  font-size: 0.93em;
  font-weight: 600;
  color: var(--accent);
  margin-bottom: 8px;
  letter-spacing: -0.01em;
}
.technique p {
  font-size: 0.88em;
  color: var(--text-muted);
  margin-bottom: 8px;
  line-height: 1.75;
}
.technique code {
  background: #1a1e2e;
  color: var(--orange);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 0.85em;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
}
.technique .impact {
  font-size: 0.84em;
  color: var(--red);
  font-weight: 600;
  line-height: 1.6;
}
.attack-chain {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  margin-top: 16px;
}
.attack-chain h4 {
  font-size: 0.9em;
  color: var(--accent2);
  margin-bottom: 10px;
}
.chain-steps {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}
.chain-step {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 5px 12px;
  border-radius: 6px;
  font-size: 0.78em;
  font-weight: 500;
  color: var(--text);
}
.chain-arrow {
  color: var(--text-muted);
  font-size: 0.8em;
}

/* Methodology section */
.principle-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 0 8px 8px 0;
  padding: 22px 26px;
  margin-bottom: 16px;
}
.principle-card h4 {
  font-size: 0.98em;
  font-weight: 700;
  color: var(--accent);
  margin-bottom: 8px;
  letter-spacing: -0.01em;
}
.principle-card p {
  font-size: 0.88em;
  color: var(--text-muted);
  line-height: 1.75;
}

/* Gap table */
.gap-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 16px;
  font-size: 0.85em;
}
.gap-table th {
  background: var(--surface2);
  color: var(--text-muted);
  padding: 10px 12px;
  text-align: left;
  font-weight: 700;
  border-bottom: 2px solid var(--border);
  font-size: 0.82em;
  letter-spacing: 0;
}
.gap-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.gap-table tr:hover { background: var(--surface2); }
.priority-1 { color: var(--red); font-weight: 600; }
.priority-2 { color: var(--orange); font-weight: 600; }

/* Tools table */
.tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
  margin-top: 16px;
}
.tool-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
}
.tool-card h4 {
  font-size: 0.88em;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 6px;
}
.tool-card p {
  font-size: 0.8em;
  color: var(--text-muted);
  line-height: 1.65;
}

/* Timeline */
.timeline {
  position: relative;
  padding-left: 24px;
  margin-top: 16px;
}
.timeline::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--border);
}
.timeline-item {
  position: relative;
  padding-bottom: 20px;
}
.timeline-item::before {
  content: '';
  position: absolute;
  left: -28px;
  top: 6px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--accent);
  border: 2px solid var(--bg);
}
.timeline-item .tl-date {
  font-size: 0.8em;
  color: var(--text-muted);
}
.timeline-item .tl-title {
  font-weight: 700;
  font-size: 0.93em;
  letter-spacing: -0.01em;
}
.timeline-item .tl-detail {
  font-size: 0.84em;
  color: var(--text-muted);
  line-height: 1.6;
}

/* Responsive */
@media (max-width: 768px) {
  header h1 { font-size: 1.8em; }
  .stats-bar { gap: 16px; }
  .card-header { flex-direction: column; }
  nav .container { gap: 4px; }
}
```

## JavaScript (include at end of body)

```javascript
// Toggle all cards open/closed with keyboard shortcut
document.addEventListener('keydown', (e) => {
  if (e.key === 'e' && e.altKey) {
    const cards = document.querySelectorAll('.card');
    const allOpen = [...cards].every(c => c.classList.contains('open'));
    cards.forEach(c => allOpen ? c.classList.remove('open') : c.classList.add('open'));
  }
});
```

## HTML Entity Reference

Use these HTML entities in the generated content:

- Arrow: `&rarr;`
- Middle dot: `&middot;`
- Section sign: `&sect;`
- Ampersand in text: `&amp;`
- Less than in text: `&lt;`
- Greater than in text: `&gt;`

## Font Stack

The `<link>` tag for Pretendard font MUST be included in `<head>`:

```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css">
```

This is the only external dependency. Everything else is inlined.
