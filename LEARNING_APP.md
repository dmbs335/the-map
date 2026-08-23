# The Map Learning App

The Map includes an offline-first companion app under [`apps/mobile`](apps/mobile).
Its job is simple: make the repository easier to learn, review, and explore.

The app follows the repository itself rather than introducing a second security
taxonomy. At build time it scans the 13 top-level The Map categories, generates a
searchable catalog, and derives a compact curriculum from the current contents.

## Learning model

Every category is studied through the same four-step loop:

```text
read the map
  -> compare cases
  -> separate observation from interpretation
  -> design a falsifiable question or control
```

This learning model borrows general research habits that are useful across
security work, without requiring a separate formal vocabulary or tying the app
to another project.

## Coverage

The curriculum contains one track for each top-level category:

1. Injection
2. Authentication & Authorization
3. HTTP & Protocol
4. Server-Side
5. Client-Side & UI
6. Encoding & Parser
7. Application Logic
8. Infrastructure & Supply Chain
9. Frameworks & Languages
10. Recon & Methodology
11. Security Researchers
12. Product Security
13. Miscellaneous & Emerging

Each track has four generated lessons: core structure, case comparison, analysis
procedure, and research-question design. The app also generates one review
question per lesson and one practice mission per category.

## Research habits

The exploration section emphasizes reusable habits:

- distinguish facts from interpretation;
- compare how different layers interpret the same value;
- re-check assumptions after time or state changes;
- trace where trusted values came from;
- use normal controls and minimal changes;
- state what would falsify a hypothesis;
- match the strength of a conclusion to the strength of its support;
- compare cases to find reusable patterns and underexplored questions.

These are presented as ordinary analysis questions, not as terminology from a
separate research framework.

## App capabilities

- generated index of all The Map Markdown topics;
- 13 category-aligned curriculum tracks;
- generated lessons, review questions, and safe practice missions;
- offline progress, bookmarks, streaks, and spaced repetition;
- direct links back to the source Markdown;
- generic case-analysis and research-question exercises;
- build-time validation that removed platform-specific and project-specific
  learning content does not return accidentally.

See [`apps/mobile/README.md`](apps/mobile/README.md) for commands and architecture.
