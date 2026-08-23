import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, '..');

async function readJson(relativePath) {
  return JSON.parse(await fs.readFile(path.join(appDir, relativePath), 'utf8'));
}

async function readText(relativePath) {
  return fs.readFile(path.join(appDir, relativePath), 'utf8');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
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
  const [curriculum, quizzes, practice, catalog] = await Promise.all([
    readJson('src/data/curriculum.json'),
    readJson('src/data/quizzes.json'),
    readJson('src/data/labs.json'),
    readJson('src/data/generated/catalog.json'),
  ]);

  assert(curriculum.schema === 'the-map.learning-curriculum.v2', 'Curriculum schema invalid');
  assert(quizzes.schema === 'the-map.learning-quizzes.v2', 'Quiz schema invalid');
  assert(practice.schema === 'the-map.learning-practice.v2', 'Practice schema invalid');
  assert(curriculum.tracks.length === 13, 'Expected exactly 13 The Map tracks');
  assert(curriculum.lessons.length >= 52, 'Expected at least 52 lessons');
  assert(quizzes.questions.length >= 52, 'Expected at least 52 review questions');
  assert(practice.missions.length === 13, 'Expected one practice mission per category');
  assert(catalog.categories.length === 13, 'Catalog must cover all 13 categories');
  assert(catalog.topics.length >= 100, 'Catalog must contain at least 100 topics');

  const trackIds = curriculum.tracks.map((track) => track.id);
  const lessonIds = curriculum.lessons.map((lesson) => lesson.id);
  const lessonSet = new Set(lessonIds);
  const trackSet = new Set(trackIds);
  const supportLevels = new Set(['idea', 'sourceBacked', 'reproduced', 'wellSupported']);

  assert(unique(trackIds), 'Track IDs must be unique');
  assert(unique(lessonIds), 'Lesson IDs must be unique');

  for (const lesson of curriculum.lessons) {
    assert(trackSet.has(lesson.trackId), `Unknown track ${lesson.trackId}`);
    assert(lesson.minutes > 0, `${lesson.id} has invalid minutes`);
    assert(lesson.objectives.length >= 3, `${lesson.id} needs at least 3 objectives`);
    assert(lesson.concepts.length >= 3, `${lesson.id} needs at least 3 concepts`);
    assert(lesson.keyQuestions.length >= 1, `${lesson.id} needs a key question`);
    assert(Boolean(lesson.safetyNote), `${lesson.id} needs a safety note`);
    assert(supportLevels.has(lesson.supportLevel), `${lesson.id} has invalid support level`);
    for (const prerequisite of lesson.prerequisiteIds) {
      assert(lessonSet.has(prerequisite), `${lesson.id} prerequisite ${prerequisite} missing`);
    }
  }
  assertAcyclic(curriculum.lessons);

  const categoryIds = new Set(catalog.categories.map((category) => category.id));
  for (let index = 1; index <= 13; index += 1) {
    const prefix = String(index).padStart(2, '0');
    const categoryId = [...categoryIds].find((id) => id.startsWith(`${prefix}-`));
    assert(categoryId, `Catalog category ${prefix} missing`);
    assert(trackSet.has(categoryId), `Curriculum track ${categoryId} missing`);
    assert(
      curriculum.lessons.filter((lesson) => lesson.trackId === categoryId).length >= 4,
      `Curriculum track ${categoryId} needs at least four lessons`,
    );
  }

  const conceptCorpus = curriculum.lessons
    .flatMap((lesson) => [lesson.title, lesson.summary, ...lesson.concepts, ...lesson.keyQuestions])
    .join(' ')
    .toLocaleLowerCase();
  const requiredConcepts = [
    'source', 'sink', 'authorization', 'message framing', 'trust boundary',
    'origin', 'normalization', 'workflow', 'cache', 'framework defaults',
    'hypothesis', 'primary source', 'threat model', 'research gap',
    'baseline', 'falsification',
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

  const missionIds = practice.missions.map((mission) => mission.id);
  assert(unique(missionIds), 'Practice IDs must be unique');
  for (const mission of practice.missions) {
    assert(mission.objectives.length >= 3, `${mission.id} objectives missing`);
    assert(mission.steps.length >= 4, `${mission.id} steps missing`);
    assert(mission.expectedSignals.length >= 2, `${mission.id} signals missing`);
    assert(supportLevels.has(mission.supportLevel), `${mission.id} support level invalid`);
    assert(Boolean(mission.safetyNote), `${mission.id} safety note missing`);
    for (const prerequisite of mission.prerequisiteLessonIds) {
      assert(lessonSet.has(prerequisite), `${mission.id} prerequisite ${prerequisite} missing`);
    }
  }

  const sourceFiles = [
    'App.tsx',
    'README.md',
    'src/types.ts',
    'src/content/researchConcepts.ts',
    'src/screens/TodayScreen.tsx',
    'src/screens/LearnScreen.tsx',
    'src/screens/LabScreen.tsx',
    'src/screens/ResearchScreen.tsx',
    'src/screens/LessonDetailScreen.tsx',
    'src/screens/MissionDetailScreen.tsx',
    'src/screens/LibraryScreen.tsx',
    'src/screens/TopicDetailScreen.tsx',
  ];
  const sourceCorpus = (
    await Promise.all(sourceFiles.map((file) => readText(file)))
  ).join('\n');
  const learningCorpus = [
    sourceCorpus,
    JSON.stringify(curriculum),
    JSON.stringify(quizzes),
    JSON.stringify(practice),
  ].join('\n');

  const removedTerms = [
    /\bjadx\b/i,
    /\bandroidmanifest\b/i,
    /\bapk\b/i,
    /\bdex\b/i,
    /\bbinder\b/i,
    /\bpendingintent\b/i,
    /\bcontentprovider\b/i,
    /\bandroid security\b/i,
    /\bmalware\b/i,
    /semantic differential/i,
    /preservation law/i,
    /evidence boundary/i,
    /deferred authorization drift/i,
    /authority laundering/i,
    /markov adequacy/i,
    /finite universe/i,
    /safety kernel/i,
    /proof-carrying/i,
    /\bmcts\b/i,
    /reinforcement learning/i,
    /policy\/value network/i,
  ];
  for (const pattern of removedTerms) {
    assert(!pattern.test(learningCorpus), `Removed domain term remains: ${pattern}`);
  }

  console.log(JSON.stringify({
    tracks: curriculum.tracks.length,
    lessons: curriculum.lessons.length,
    quizzes: quizzes.questions.length,
    practiceMissions: practice.missions.length,
    catalogTopics: catalog.topics.length,
    catalogCategories: catalog.categories.length,
    removedDomainTermsChecked: removedTerms.length,
  }));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
