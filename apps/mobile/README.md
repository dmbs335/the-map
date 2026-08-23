# The Map Learning

An offline-first companion for learning the contents of The Map.

The application mirrors the repository's 13 top-level categories and keeps the
Markdown files as the source of truth. It does not add a second vulnerability
taxonomy. Instead it provides a learning layer around the existing map:

```text
The Map documents
  -> generated catalog
  -> four lessons per category
  -> spaced-repetition review
  -> case-comparison practice
  -> research-question habits
```

## Curriculum

At build time, `scripts/generate-catalog.mjs` scans the repository and writes a
searchable catalog. `scripts/generate-learning-content.mjs` then derives:

- 13 curriculum tracks, one per top-level The Map category;
- 52 lessons, four per category;
- one review question per lesson;
- 13 practice missions, one per category.

The four lesson stages are:

1. read the core structure;
2. compare cases and failure conditions;
3. separate evidence from interpretation and design controls;
4. turn underexplored combinations into falsifiable questions.

## Exploration habits

The app keeps a small set of general research habits that are useful across The
Map:

- facts versus interpretation;
- same input, different interpretation;
- re-checking assumptions after state changes;
- tracing the origin of trusted values;
- matched controls and counterexamples;
- support level versus conclusion strength;
- comparing cases for common structure;
- turning gaps into falsifiable questions.

These are ordinary analysis prompts rather than terminology imported from a
separate project.

## Offline learning state

Progress, bookmarks, mission completion, and spaced-repetition reviews are
persisted locally through `expo-sqlite/kv-store`. The app does not upload learning
progress or source documents.

## Generated catalog

`scripts/generate-catalog.mjs` scans every Markdown file under the 13 categories
and writes:

```text
src/data/generated/catalog.json
```

The catalog stores title, summary, tags, category, source URL, and verified-list
membership. Full documents remain in the repository and can be opened from the
app.

## Commands

From `apps/mobile`:

```bash
npm install
npm run prepare:content
npm run validate:curriculum
npm run typecheck
npm run export:android
npm start
```

`prepare:content` regenerates both the catalog and learning content from the
current repository. `npm run check` runs generation, curriculum validation, and
TypeScript checking.

## Scope

The learning content is about The Map. Platform-specific reverse-engineering
courses, binary-analysis imports, malicious-behavior triage, and terminology
owned by other research projects are deliberately outside this app's curriculum.

Practice remains limited to public material, synthetic examples, or explicitly
authorized environments.
