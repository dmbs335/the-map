# Mobile Learning App

The Map includes a companion app under [`apps/mobile`](apps/mobile). It combines
three knowledge sources:

1. **The Map** — comprehensive web-security mutation taxonomy and reference
   library;
2. **JADX** — Android APK observation and static-analysis workflow;
3. **websec-formal** — semantic differential, evidence-bound research
   discovery, and algorithm-independent search-environment theory.

## Why this exists

A mobile-security learner must connect platform facts to security meaning:

```text
Manifest or bytecode observation
  -> attack-surface hypothesis
  -> subject / target / provenance / lifecycle model
  -> local control experiment
  -> evidence-bounded report
```

A checklist-only app misses the difficult parts: reflection and native-code
limits, malicious-behavior ambiguity, backend/web dependencies, authorization
lifetime, provenance loss, false-positive controls, and the boundary between a
formal candidate and an implementation finding. The companion app covers those
missing layers explicitly.

## Major capabilities

- 13 curriculum tracks and 90+ lessons;
- complete generated index of all The Map topic Markdown files;
- JADX learning-report JSON import with strict safety validation;
- synthetic APK analysis report and guided missions;
- Android vulnerability and malicious-behavior tracks;
- spaced-repetition quiz queue;
- offline progress, bookmarks, and mission state;
- semantic/formal research reference, including Deferred Authorization Drift,
  Authority Laundering, Markov adequacy, finite closure, and safety kernels;
- Android export and CI validation.

See [`apps/mobile/README.md`](apps/mobile/README.md) for architecture, report
schema, commands, and safety limits.
