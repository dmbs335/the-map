export interface ResearchConcept {
  id: string;
  title: string;
  lessonId: string;
  status: 'operational' | 'theory' | 'future';
  summary: string;
  whyItMatters: string;
  checks: string[];
}

export const researchConcepts: ResearchConcept[] = [
  {
    id: 'semantic-differential',
    title: 'Semantic Differential',
    lessonId: 'semantic-differential',
    status: 'operational',
    summary: '검사 계층과 실제 소비 계층이 같은 입력을 다른 의미로 해석하는 지점을 찾는다.',
    whyItMatters: '취약점 이름보다 parser·authority·lifecycle mismatch를 재사용 가능한 구조로 표현할 수 있다.',
    checks: ['입력 carrier는 무엇인가?', 'validator와 consumer의 projection은 무엇인가?', '차이가 어떤 capability로 이어지는가?'],
  },
  {
    id: 'preservation-laws',
    title: 'Preservation Laws',
    lessonId: 'preservation-laws',
    status: 'operational',
    summary: 'representation, boundary, binding, precedence, provenance, lifecycle, data/control 보존 실패를 분류한다.',
    whyItMatters: '서로 다른 취약점 family의 공통 원인을 비교하고 새로운 빈 좌표를 만들 수 있다.',
    checks: ['무엇이 보존되어야 했나?', '어느 transition에서 깨졌나?', 'mitigation이 원인 법칙을 복구하나?'],
  },
  {
    id: 'deferred-authorization',
    title: 'Deferred Authorization Drift',
    lessonId: 'deferred-authorization-drift',
    status: 'theory',
    summary: 'check 시점의 subject·target·epoch·resource version이 use 시점에 더 이상 유효하지 않은 상태를 모델링한다.',
    whyItMatters: 'PendingIntent, background work, queue, retry, approval workflow와 mobile lifecycle의 권한 버그를 한 구조로 묶는다.',
    checks: ['authorization certificate에 무엇이 binding됐나?', '어떤 state transition이 certificate를 무효화하나?', 'use 시점 재검증이 있는가?'],
  },
  {
    id: 'authority-laundering',
    title: 'Authority Laundering',
    lessonId: 'authority-laundering',
    status: 'theory',
    summary: '검증된 identity가 String, Bundle, header, queue metadata로 평탄화되며 trust provenance를 잃는 경로를 추적한다.',
    whyItMatters: 'Binder identity→Intent extra, JWT principal→header, signer→package name 같은 모바일·백엔드 경계를 함께 분석할 수 있다.',
    checks: ['값의 trusted source는 무엇인가?', '어떤 transform이 provenance를 지우나?', 'consumer가 다시 검증하는가?'],
  },
  {
    id: 'typed-semantic-state',
    title: 'Typed Semantic State',
    lessonId: 'semantic-state-transition',
    status: 'theory',
    summary: 'principal, resource, binding, provenance, observation, capability, lifecycle, world version을 탐색 상태로 만든다.',
    whyItMatters: 'raw HTTP/APK input보다 작고 보안 의미가 있는 state space를 정의한다.',
    checks: ['hidden history가 상태 밖에 남아 있나?', 'mutation precondition이 명확한가?', 'successor가 결정적인가?'],
  },
  {
    id: 'markov-adequacy',
    title: 'Markov Adequacy & Quotient',
    lessonId: 'markov-finite-universe',
    status: 'theory',
    summary: '같은 abstract state와 action이 hidden concrete history에 따라 다른 successor를 만들지 않는지 증명한다.',
    whyItMatters: 'state compression이나 future MCTS가 잘못된 equivalence class 위에서 탐색하는 것을 막는다.',
    checks: ['probe가 중요한 차이를 보존하나?', 'operator congruence가 성립하나?', 'finite universe가 closure를 만족하나?'],
  },
  {
    id: 'proof-carrying-harness',
    title: 'Proof-Carrying Harness',
    lessonId: 'proof-carrying-finding',
    status: 'operational',
    summary: 'baseline, adversarial, mitigation과 exact evidence locator를 묶어 promotion obligation을 닫는다.',
    whyItMatters: '그럴듯한 가설과 실제 구현 finding을 증거 경계로 분리한다.',
    checks: ['동일 초기 상태인가?', 'matched negative control이 있는가?', 'artifact와 replay command가 고정됐나?'],
  },
  {
    id: 'mcts-readiness',
    title: 'MCTS Readiness — Non-goal',
    lessonId: 'safety-kernel-mcts-readiness',
    status: 'future',
    summary: '현재는 state/action/transition/invariant/refinement/finite closure만 정의하고 MCTS·RL·learned reward는 구현하지 않는다.',
    whyItMatters: '탐색 알고리즘보다 환경 의미와 soundness를 먼저 고정해야 한다.',
    checks: ['state가 Markov-adequate한가?', 'action basis가 유한한가?', 'abstract violation을 concrete evidence로 내리는 계약이 있는가?'],
  },
];
