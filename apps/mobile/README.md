# JADX Security Learning Lab

An offline-first Expo mobile learning app for Android application security,
malicious-behavior analysis, web/backend attack surfaces, and formal semantic
reasoning.

The app is designed around one loop:

```text
observe an APK/JADX artifact
  -> form a security hypothesis
  -> identify assumptions and evidence limits
  -> design baseline / adversarial / mitigation controls
  -> promote only evidence-backed conclusions
```

## Coverage

The curriculum is intentionally broader than a vulnerability checklist. It
contains 13 tracks and more than 90 lessons covering:

- APK, AAB, Manifest, DEX, components, IPC, Binder, permissions, signing, and
  Android sandbox boundaries;
- JADX navigation, cross references, call graphs, data flow, reflection,
  obfuscation, JNI, version diffing, and evidence-centered reporting;
- exported components, ContentProvider, deep links, PendingIntent, WebView,
  JavaScript bridges, FileProvider, notification actions, and inter-app trust;
- local storage, Android Keystore, TLS, tokens, native code, dynamic loading,
  mobile SDKs, and supply-chain provenance;
- malware triage, C2, persistence, Accessibility abuse, overlays, OTP
  collection, surveillance, droppers, anti-analysis, and destructive behavior;
- safe emulator/ADB labs, runtime instrumentation concepts, network
  observation, state diffing, and sandboxed behavior validation;
- all 13 top-level categories in The Map;
- semantic differentials, preservation laws, carriers, observers,
  capabilities, evidence boundaries, Deferred Authorization Drift, and
  Authority Laundering;
- research-gap mining, falsification, benchmarking, proof-carrying harnesses,
  semantic state/transition theory, abstraction/refinement, observational
  equivalence, Markov adequacy, finite state universes, and safety kernels.

MCTS, reinforcement learning, policy/value networks, and learned rewards are
explicit non-goals. The app teaches the formal environment that a future search
optimizer would require.

## JADX report import

The Lab tab accepts a safe JSON interchange format:

```text
jadx-learning-report.v1
```

A report contains app identity, Manifest components, permissions, native
libraries, finding candidates, behavior signals, data-flow summaries, evidence
locators, assumptions, negative controls, and analysis limits.

The importer rejects reports that:

- do not declare `syntheticOrAuthorizedOnly: true`;
- claim to include executable payloads;
- use an unknown schema;
- omit required evidence-boundary fields;
- contain inconsistent summary counts.

The repository includes a synthetic report for
`com.example.training.wallet`. It is not associated with a real app or target.

## Offline learning state

Progress, bookmarks, mission completion, spaced-repetition reviews, and the last
accepted report are persisted locally through `expo-sqlite/kv-store`.

The app does not upload APKs, reports, findings, or learning progress.

## Generated The Map catalog

At build time, `scripts/generate-catalog.mjs` scans all top-level The Map
categories and writes:

```text
src/data/generated/catalog.json
```

The generated catalog supplies title, summary, tags, category, source URL, and
`VERIFIED_ONLY.md` membership. The full Markdown documents remain the source of
truth.

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

`npm install` restores the bundled curriculum, quiz, lab, and synthetic JADX
report JSON before generating the catalog. `npm run check` performs restoration,
catalog generation, curriculum validation, and TypeScript checking together.

## Safety boundary

This app is a learning and analysis companion. It does not:

- execute imported APKs;
- deliver payloads;
- automate attacks against third-party systems;
- convert model-only hypotheses into product findings;
- classify an app as malware from a single permission or API call.

Dynamic validation belongs in a separate local, resettable, isolated lab using
synthetic data or explicitly authorized samples.
