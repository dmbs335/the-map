import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, '..');
const dataDir = path.join(appDir, 'src', 'data');
const catalogPath = path.join(dataDir, 'generated', 'catalog.json');

const colors = [
  '#7C9FFF', '#8AD1C2', '#F1B36B', '#C69CFF', '#7FC8FF', '#F28DB2', '#9DD47A',
  '#F0D264', '#83B5FF', '#B8A0FF', '#6FD0B5', '#FF9E8A', '#A6B5C9',
];

const levelByIndex = ['foundation', 'foundation', 'practitioner', 'advanced'];
const supportByIndex = ['sourceBacked', 'sourceBacked', 'reproduced', 'idea'];

const categoryGuidance = {
  '01-injection': {
    concepts: ['source', 'sink', 'context', 'encoding', 'baseline', 'falsification'],
    focus: '입력의 출처와 최종 소비 지점을 연결하고, 문맥에 따라 같은 값의 의미가 어떻게 달라지는지 확인한다.',
    questions: ['입력은 어디서 통제되는가?', '최종 소비 문맥은 무엇인가?', '정상 대조군에서 무엇이 달라져야 하는가?'],
  },
  '02-auth': {
    concepts: ['identity', 'authorization', 'session', 'object binding', 'time of check', 'revalidation'],
    focus: '누가 누구의 권한으로 어떤 대상에 행동할 수 있는지, 그리고 그 판단이 사용 시점까지 유효한지 확인한다.',
    questions: ['주체와 대상은 무엇인가?', '권한 판단 뒤 바뀔 수 있는 상태는 무엇인가?', '사용 직전 다시 확인하는가?'],
  },
  '03-http-protocol': {
    concepts: ['message framing', 'request boundary', 'proxy', 'backend', 'normalization', 'differential'],
    focus: '여러 HTTP 처리 계층이 메시지 경계와 필드 의미를 동일하게 해석하는지 비교한다.',
    questions: ['각 계층의 메시지 경계는 같은가?', '중간 계층이 필드를 다시 쓰는가?', '서로 다른 해석을 최소 입력으로 재현할 수 있는가?'],
  },
  '04-server-side': {
    concepts: ['trust boundary', 'filesystem', 'network access', 'serialization', 'template', 'control flow'],
    focus: '서버가 외부 값을 신뢰 경계 안으로 들일 때 어떤 기능과 자원 접근이 열리는지 추적한다.',
    questions: ['외부 값이 어느 기능에 영향을 주는가?', '서버 내부 권한으로 무엇을 할 수 있는가?', '입력 검증과 실제 사용 사이에 변환이 있는가?'],
  },
  '05-client-side': {
    concepts: ['origin', 'document', 'DOM', 'navigation', 'message', 'trust boundary'],
    focus: '브라우저 안에서 문서, origin, 메시지, 사용자 상호작용의 신뢰 경계가 어떻게 바뀌는지 본다.',
    questions: ['누가 현재 문서를 통제하는가?', '확인 시점과 사용 시점의 대상이 같은가?', '브라우저가 제공하는 경계가 어디까지인가?'],
  },
  '06-encoding-parser': {
    concepts: ['normalization', 'canonical form', 'parser', 'encoding', 'ambiguity', 'differential'],
    focus: '같은 바이트나 문자열이 변환 순서와 parser에 따라 다른 의미가 되는 조건을 찾는다.',
    questions: ['정규화 순서는 같은가?', '한 계층이 허용한 값을 다음 계층은 어떻게 읽는가?', '같은 의미를 갖는 표현과 다른 의미를 갖는 표현을 구분할 수 있는가?'],
  },
  '07-application-logic': {
    concepts: ['workflow', 'state transition', 'invariant', 'race', 'business rule', 'replay'],
    focus: '개별 입력 검증보다 업무 흐름과 상태 전환 사이에서 깨지는 가정을 찾는다.',
    questions: ['정상 상태 전환 순서는 무엇인가?', '순서를 바꾸거나 반복하면 어떤 가정이 깨지는가?', '동시성이나 재시도에서 상태가 달라지는가?'],
  },
  '08-infrastructure': {
    concepts: ['trust boundary', 'provenance', 'proxy', 'cache', 'supply chain', 'configuration'],
    focus: '여러 서비스와 운영 계층을 지나며 값의 출처와 신뢰 근거가 어떻게 보존되는지 확인한다.',
    questions: ['이 값은 누가 만들었는가?', '중간 계층이 출처 정보를 잃게 만드는가?', '최종 소비자는 원래 신뢰 근거를 확인할 수 있는가?'],
  },
  '09-frameworks-and-languages': {
    concepts: ['framework defaults', 'language semantics', 'binding', 'deserialization', 'implicit behavior', 'configuration'],
    focus: '프레임워크와 언어가 자동으로 제공하는 변환·바인딩·기본값이 보안 가정을 바꾸는 지점을 본다.',
    questions: ['개발자가 쓰지 않은 동작을 프레임워크가 추가하는가?', '기본값이 버전마다 달라지는가?', '같은 코드를 다른 구성에서 실행하면 의미가 달라지는가?'],
  },
  '10-recon-methodology': {
    concepts: ['hypothesis', 'observation', 'primary source', 'fact vs interpretation', 'negative evidence', 'scope'],
    focus: '수집한 정보를 사실과 해석으로 분리하고, 다음 검증을 가장 많이 줄여주는 질문을 선택한다.',
    questions: ['직접 확인한 사실은 무엇인가?', '추론에 필요한 가정은 무엇인가?', '다음 한 번의 관찰로 어떤 가설을 가장 많이 제거할 수 있는가?'],
  },
  '11-researchers': {
    concepts: ['primary source', 'case study', 'hypothesis', 'method', 'counterexample', 'generalization'],
    focus: '공개 연구를 결과보다 사고 과정 중심으로 읽고, 서로 다른 사례에서 재사용 가능한 질문을 추출한다.',
    questions: ['연구자는 처음 무엇을 이상하게 봤는가?', '어떤 반례를 제거했는가?', '다른 시스템에도 적용되는 부분과 특정 구현에만 해당하는 부분은 무엇인가?'],
  },
  '12-product-security': {
    concepts: ['threat model', 'attack surface', 'support level', 'reproduction', 'mitigation', 'residual risk'],
    focus: '제품 맥락에서 위협 모델, 재현, 영향, 수정, 잔여 위험을 분리해 판단한다.',
    questions: ['누가 어떤 조건에서 공격 가능한가?', '재현 가능한 최소 조건은 무엇인가?', '수정 후에도 남는 경로가 있는가?'],
  },
  '13-misc': {
    concepts: ['research gap', 'cross-category pattern', 'analogy', 'falsification', 'novelty', 'uncertainty'],
    focus: '기존 범주 사이의 연결과 빈칸을 찾아 새로운 질문을 만들되, 먼저 틀릴 수 있는 이유를 적는다.',
    questions: ['정말 새로운 빈칸인가?', '유사 사례와 핵심 조건이 같은가?', '가설을 가장 빨리 반박할 최소 검증은 무엇인가?'],
  },
};

const lessonKinds = [
  {
    suffix: '01',
    title: '핵심 구조 읽기',
    practiceType: 'map-reading',
    summary: (category, guide) => `${category.title} 범주의 대표 주제와 반복되는 구조를 The Map 원문에서 찾는다. ${guide.focus}`,
    objective: ['대표 문서의 공통 질문을 설명한다.', '주요 입력·상태·신뢰 경계를 구분한다.', '원문과 요약을 함께 읽고 직접 근거를 표시한다.'],
  },
  {
    suffix: '02',
    title: '사례 비교와 실패 조건',
    practiceType: 'case-comparison',
    summary: (category) => `${category.title} 사례 둘 이상을 비교해 겉모습과 실제 실패 조건을 분리한다.`,
    objective: ['두 사례의 공통 조건과 차이를 표로 정리한다.', '취약점 이름보다 실제 실패 조건을 설명한다.', '성립하지 않는 반례를 하나 이상 찾는다.'],
  },
  {
    suffix: '03',
    title: '분석 절차와 근거',
    practiceType: 'evidence-review',
    summary: (category) => `${category.title} 문제를 관찰→가설→대조→검증 순서로 분석하고 결론의 근거 수준을 표시한다.`,
    objective: ['직접 관찰과 추론을 분리한다.', '정상 대조군과 최소 변형을 설계한다.', '결론보다 약한 증거를 과장하지 않는다.'],
  },
  {
    suffix: '04',
    title: '빈칸에서 연구 질문 만들기',
    practiceType: 'research-question',
    summary: (category) => `${category.title} 내부와 다른 범주 사이에서 덜 다뤄진 조합을 찾아 반박 가능한 질문으로 바꾼다.`,
    objective: ['기존 사례의 범위를 명확히 한다.', '새 질문이 단순 중복인지 확인한다.', '가설을 반박할 가장 작은 실험을 설계한다.'],
  },
];

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function titleCaseTopic(topic) {
  return topic?.title || '대표 사례';
}

function topSourceRefs(topics) {
  return topics.slice(0, 4).map((topic) => topic.path);
}

function conceptsFor(topics, guide, kindIndex) {
  const tags = topics.flatMap((topic) => topic.tags ?? []).slice(0, 6);
  const methodConcepts = [
    ['map', 'taxonomy', 'source reading'],
    ['comparison', 'failure condition', 'counterexample'],
    ['baseline', 'falsification', 'support level'],
    ['research gap', 'analogy', 'minimal experiment'],
  ][kindIndex];
  return unique([...guide.concepts, ...tags, ...methodConcepts]).slice(0, 10);
}

function makeLessons(catalog) {
  const lessons = [];
  for (const [categoryIndex, category] of catalog.categories.entries()) {
    const guide = categoryGuidance[category.id];
    if (!guide) throw new Error(`missing guidance for ${category.id}`);
    const topics = catalog.topics.filter((topic) => topic.categoryId === category.id);
    for (const [kindIndex, kind] of lessonKinds.entries()) {
      const id = `${category.id}-${kind.suffix}`;
      lessons.push({
        id,
        trackId: category.id,
        order: kindIndex + 1,
        title: `${kindIndex + 1}. ${kind.title}`,
        level: levelByIndex[kindIndex],
        minutes: [15, 20, 25, 25][kindIndex],
        summary: kind.summary(category, guide),
        objectives: kind.objective,
        concepts: conceptsFor(topics, guide, kindIndex),
        relatedCategories: [category.id],
        prerequisiteIds: kindIndex === 0 ? [] : [`${category.id}-0${kindIndex}`],
        practiceType: kind.practiceType,
        supportLevel: supportByIndex[kindIndex],
        safetyNote: '공개 자료, 합성 예제, 또는 명시적으로 허가된 환경에서만 검증한다.',
        keyQuestions: guide.questions,
        sourceRefs: topSourceRefs(topics),
      });
    }
  }
  return lessons;
}

function makeTracks(catalog) {
  return catalog.categories.map((category, index) => ({
    id: category.id,
    title: category.title,
    description: `${category.topicCount}개 The Map 문서를 핵심 구조, 사례 비교, 분석 절차, 연구 질문의 네 단계로 학습한다.`,
    level: index < 3 ? 'foundation' : index < 9 ? 'practitioner' : 'advanced',
    color: colors[index % colors.length],
  }));
}

function makeQuizzes(catalog, lessons) {
  const questions = [];
  for (const lesson of lessons) {
    const category = catalog.categories.find((item) => item.id === lesson.trackId);
    const topic = catalog.topics.find((item) => item.categoryId === lesson.trackId);
    questions.push({
      id: `quiz:${lesson.id}`,
      lessonId: lesson.id,
      kind: lesson.order >= 3 ? 'scenario' : 'multipleChoice',
      prompt: `${category.title} 사례를 분석할 때 가장 먼저 해야 할 일은?`,
      options: [
        '직접 관찰한 사실과 추론을 분리하고 현재 가정을 적는다.',
        '가장 심각해 보이는 취약점 이름부터 확정한다.',
        '대조군 없이 한 번의 결과로 원인을 확정한다.',
        '원문보다 기억에 의존해 영향 범위를 넓힌다.',
      ],
      answerIndex: 0,
      explanation: `${titleCaseTopic(topic)} 같은 사례도 먼저 사실·가정·대조 조건을 분리해야 원인과 영향 범위를 과장하지 않는다.`,
      tags: unique([lesson.trackId, lesson.practiceType, ...lesson.concepts.slice(0, 3)]),
    });
  }
  return questions;
}

function makeMissions(catalog) {
  return catalog.categories.map((category, index) => {
    const guide = categoryGuidance[category.id];
    const topics = catalog.topics.filter((topic) => topic.categoryId === category.id);
    const examples = topics.slice(0, 3).map((topic) => topic.title);
    return {
      id: `practice:${category.id}`,
      title: `${category.title} 사례 비교`,
      level: index < 4 ? 'foundation' : index < 10 ? 'practitioner' : 'advanced',
      minutes: 30,
      summary: `${category.title}의 공개 사례를 비교해 공통 조건, 반례, 검증 계획을 작성한다.`,
      objectives: [
        '관찰 사실과 해석을 분리한다.',
        '두 사례의 공통 조건과 차이를 비교한다.',
        '정상 대조군과 최소 반례를 설계한다.',
      ],
      steps: [
        `The Map에서 ${examples.join(', ') || '대표 문서'} 중 두 개를 고른다.`,
        '각 사례에서 직접 확인 가능한 사실만 별도 목록으로 적는다.',
        '공통 실패 조건과 서로 다른 구현 세부를 두 열로 나눈다.',
        '가설을 반박할 정상 대조군 또는 최소 변형을 설계한다.',
        '결론의 근거 수준과 아직 남은 가정을 적는다.',
      ],
      expectedSignals: [
        guide.focus,
        `확인 질문: ${guide.questions[0]}`,
        '결론보다 강한 주장을 하지 않고 남은 불확실성을 명시한다.',
      ],
      hints: guide.questions,
      prerequisiteLessonIds: [`${category.id}-03`],
      focusAreas: guide.concepts.slice(0, 5),
      supportLevel: 'sourceBacked',
      safetyNote: '공개 자료, 합성 예제, 또는 명시적으로 허가된 환경만 사용한다.',
      sourceRefs: topSourceRefs(topics),
    };
  });
}

async function main() {
  const catalog = JSON.parse(await fs.readFile(catalogPath, 'utf8'));
  if (catalog.categories.length < 13) {
    throw new Error(`expected 13 categories, found ${catalog.categories.length}`);
  }
  const tracks = makeTracks(catalog);
  const lessons = makeLessons(catalog);
  const questions = makeQuizzes(catalog, lessons);
  const missions = makeMissions(catalog);

  const outputs = [
    ['curriculum.json', { schema: 'the-map.learning-curriculum.v2', tracks, lessons }],
    ['quizzes.json', { schema: 'the-map.learning-quizzes.v2', questions }],
    ['labs.json', { schema: 'the-map.learning-practice.v2', missions }],
  ];

  await fs.mkdir(dataDir, { recursive: true });
  for (const [name, value] of outputs) {
    await fs.writeFile(path.join(dataDir, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  }
  console.log(JSON.stringify({ tracks: tracks.length, lessons: lessons.length, quizzes: questions.length, missions: missions.length }));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
