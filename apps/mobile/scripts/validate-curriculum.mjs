import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, '..');

async function readJson(relativePath) {
  return JSON.parse(await fs.readFile(path.join(appDir, relativePath), 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function unique(values) {
  return new Set(values).size === values.length;
}

function assertAcyclic(lessons) {
  const byId = new Map(lessons.map((lesson) => [lesson.id, lesson]));
  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visited.has(id)) return;
    if (visiting.has(id)) throw new Error(`Curriculum prerequisite cycle at ${id}`);
    visiting.add(id);
    const lesson = byId.get(id);
    for (const prerequisite of lesson?.prerequisiteIds ?? []) visit(prerequisite);
    visiting.delete(id);
    visited.add(id);
  }
  for (const lesson of lessons) visit(lesson.id);
}

async function main() {
  const [curriculum, quizzes, labs, catalog, sample] = await Promise.all([
    readJson('src/data/curriculum.json'),
    readJson('src/data/quizzes.json'),
    readJson('src/data/labs.json'),
    readJson('src/data/generated/catalog.json'),
    readJson('src/data/samples/jadx-learning-report.json'),
  ]);

  assert(curriculum.tracks.length >= 13, 'Expected at least 13 curriculum tracks');
  assert(curriculum.lessons.length >= 90, 'Expected at least 90 lessons');
  assert(quizzes.questions.length >= 70, 'Expected at least 70 quiz questions');
  assert(labs.missions.length >= 12, 'Expected at least 12 lab missions');
  assert(catalog.categories.length >= 13, 'Catalog must cover all 13 categories');
  assert(catalog.topics.length >= 100, 'Catalog must contain at least 100 topics');

  const trackIds = curriculum.tracks.map((track) => track.id);
  const lessonIds = curriculum.lessons.map((lesson) => lesson.id);
  assert(unique(trackIds), 'Track IDs must be unique');
  assert(unique(lessonIds), 'Lesson IDs must be unique');
  const lessonSet = new Set(lessonIds);
  const trackSet = new Set(trackIds);
  const boundaries = new Set([
    'modelOnly', 'symbolicWitness', 'syntheticHarness',
    'implementationHarness', 'checkedFinding',
  ]);

  for (const lesson of curriculum.lessons) {
    assert(trackSet.has(lesson.trackId), `Unknown track ${lesson.trackId}`);
    assert(lesson.minutes > 0, `${lesson.id} has invalid minutes`);
    assert(lesson.objectives.length >= 3, `${lesson.id} needs at least 3 objectives`);
    assert(lesson.concepts.length >= 3, `${lesson.id} needs at least 3 concepts`);
    assert(lesson.keyQuestions.length >= 1, `${lesson.id} needs a key question`);
    assert(Boolean(lesson.safetyNote), `${lesson.id} needs a safety note`);
    assert(boundaries.has(lesson.evidenceBoundary), `${lesson.id} has invalid evidence boundary`);
    for (const prerequisite of lesson.prerequisiteIds) {
      assert(lessonSet.has(prerequisite), `${lesson.id} prerequisite ${prerequisite} missing`);
    }
  }
  assertAcyclic(curriculum.lessons);

  const categoryIds = new Set(catalog.categories.map((category) => category.id));
  for (let index = 1; index <= 13; index += 1) {
    const prefix = String(index).padStart(2, '0');
    assert(
      [...categoryIds].some((id) => id.startsWith(`${prefix}-`)),
      `Catalog category ${prefix} missing`,
    );
    assert(
      curriculum.lessons.some((lesson) =>
        lesson.relatedCategories.some((category) => category.startsWith(`${prefix}-`)),
      ),
      `Curriculum does not cover category ${prefix}`,
    );
  }

  const conceptCorpus = curriculum.lessons
    .flatMap((lesson) => [lesson.title, lesson.summary, ...lesson.concepts])
    .join(' ')
    .toLocaleLowerCase();
  const requiredConcepts = [
    'apk', 'androidmanifest', 'dex', 'activity', 'service', 'broadcastreceiver',
    'contentprovider', 'intent', 'binder', 'permission', 'signer', 'sandbox',
    'jadx', 'call graph', 'reflection', 'obfuscation', 'jni', 'exported',
    'deep link', 'pendingintent', 'webview', 'storage', 'keystore', 'tls',
    'dynamic code', 'supply chain', 'c2', 'persistence', 'accessibility',
    'overlay', 'otp', 'exfiltration', 'dropper', 'anti-debug', 'ransomware',
    'adb', 'runtime instrumentation', 'semantic differential', 'preservation law',
    'carrier', 'observer', 'capability', 'evidence boundary',
    'deferred authorization drift', 'authority laundering', 'semantic state',
    'invariant', 'reachability', 'refinement', 'observational equivalence',
    'markov adequacy', 'finite universe', 'safety kernel', 'mcts readiness',
  ];
  for (const concept of requiredConcepts) {
    assert(conceptCorpus.includes(concept), `Required concept missing: ${concept}`);
  }

  const questionIds = quizzes.questions.map((question) => question.id);
  assert(unique(questionIds), 'Quiz IDs must be unique');
  for (const question of quizzes.questions) {
    assert(lessonSet.has(question.lessonId), `${question.id} lesson missing`);
    assert(question.options.length >= 2, `${question.id} needs options`);
    assert(
      Number.isInteger(question.answerIndex) &&
        question.answerIndex >= 0 &&
        question.answerIndex < question.options.length,
      `${question.id} answerIndex invalid`,
    );
    assert(Boolean(question.explanation), `${question.id} explanation missing`);
  }

  const missionIds = labs.missions.map((mission) => mission.id);
  assert(unique(missionIds), 'Mission IDs must be unique');
  for (const mission of labs.missions) {
    assert(mission.objectives.length >= 3, `${mission.id} objectives missing`);
    assert(mission.steps.length >= 4, `${mission.id} steps missing`);
    assert(mission.expectedSignals.length >= 2, `${mission.id} signals missing`);
    assert(Boolean(mission.safetyNote), `${mission.id} safety note missing`);
    for (const prerequisite of mission.prerequisiteLessonIds) {
      assert(lessonSet.has(prerequisite), `${mission.id} prerequisite ${prerequisite} missing`);
    }
  }

  assert(sample.schema === 'jadx-learning-report.v1', 'Sample report schema invalid');
  assert(sample.safety.syntheticOrAuthorizedOnly === true, 'Sample scope must be safe');
  assert(sample.safety.executablePayloadsIncluded === false, 'Sample cannot contain payloads');
  assert(sample.summary.findingCount === sample.findings.length, 'Sample finding count mismatch');
  assert(sample.summary.behaviorSignalCount === sample.behaviorSignals.length, 'Sample signal count mismatch');
  assert(
    curriculum.lessons.some((lesson) =>
      lesson.id === 'safety-kernel-mcts-readiness' &&
      lesson.summary.toLocaleLowerCase().includes('구현하지 않는다'),
    ),
    'MCTS non-goal must be explicit',
  );

  console.log(JSON.stringify({
    tracks: curriculum.tracks.length,
    lessons: curriculum.lessons.length,
    quizzes: quizzes.questions.length,
    missions: labs.missions.length,
    catalogTopics: catalog.topics.length,
    catalogCategories: catalog.categories.length,
    sampleFindings: sample.findings.length,
    sampleSignals: sample.behaviorSignals.length,
  }));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
