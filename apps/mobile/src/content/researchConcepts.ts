export interface ResearchConcept {
  id: string;
  title: string;
  lessonId: string;
  status: 'core' | 'practice' | 'explore';
  summary: string;
  whyItMatters: string;
  checks: string[];
}

export const researchConcepts: ResearchConcept[] = [
  {
    id: 'fact-vs-interpretation',
    title: '사실과 해석 분리',
    lessonId: '10-recon-methodology-03',
    status: 'core',
    summary: '로그·응답·문서에 직접 나타난 사실과 그 사실에 대한 추론을 다른 줄에 기록한다.',
    whyItMatters: '관찰되지 않은 부분을 무심코 사실처럼 채우는 순간 분석의 신뢰도가 급격히 떨어진다.',
    checks: ['직접 본 것은 무엇인가?', '추론한 것은 무엇인가?', '추론을 반박할 증거는 무엇인가?'],
  },
  {
    id: 'different-interpretations',
    title: '같은 입력, 다른 해석',
    lessonId: '06-encoding-parser-04',
    status: 'practice',
    summary: '검사 단계와 실제 처리 단계가 같은 값을 다르게 읽는지 동일 입력으로 비교한다.',
    whyItMatters: '많은 우회는 새로운 문자열 자체보다 계층 사이의 해석 차이에서 생긴다.',
    checks: ['두 단계가 같은 값과 타입을 보는가?', '변환 순서가 같은가?', '오류 처리도 같은가?'],
  },
  {
    id: 'time-and-recheck',
    title: '시간이 흐르면 다시 묻기',
    lessonId: '02-auth-04',
    status: 'core',
    summary: '검사와 실제 사용 사이에 상태·권한·대상이 바뀔 수 있다면 과거 판단의 유효성을 다시 확인한다.',
    whyItMatters: 'queue, retry, 승인 대기처럼 시간이 끼는 흐름은 짧은 요청 처리와 다른 실패 조건을 만든다.',
    checks: ['검사 뒤 무엇이 바뀔 수 있는가?', '어떤 변화가 과거 판단을 무효화하는가?', '사용 직전 재확인이 있는가?'],
  },
  {
    id: 'trust-origin',
    title: '신뢰의 출처 따라가기',
    lessonId: '08-infrastructure-01',
    status: 'practice',
    summary: '신뢰된 값이 여러 계층을 거칠 때 누가 만들었고 어떤 변환을 거쳤는지 끝까지 추적한다.',
    whyItMatters: '값이 같아 보여도 검증된 값과 외부가 주입한 값은 같은 권한으로 취급되면 안 된다.',
    checks: ['최초 신뢰 근거는 무엇인가?', '중간 변환에서 출처 정보가 사라지는가?', '최종 소비자가 다시 확인하는가?'],
  },
  {
    id: 'controls-and-counterexamples',
    title: '대조군과 반례',
    lessonId: '01-injection-04',
    status: 'core',
    summary: '정상 사례, 최소 변형 사례, 수정된 방어를 같은 환경에서 비교한다.',
    whyItMatters: '결과 하나만으로는 원인을 알기 어렵고, 대조군이 있어야 어떤 차이가 현상을 만들었는지 좁힐 수 있다.',
    checks: ['한 번에 하나의 변수만 바꿨는가?', '정상 대조군은 통과하는가?', '수정안이 원인을 제거하는가?'],
  },
  {
    id: 'support-level',
    title: '결론의 강도를 증거에 맞추기',
    lessonId: '12-product-security-03',
    status: 'core',
    summary: '아이디어, 출처가 있는 주장, 직접 재현, 충분히 지지된 결론을 구분한다.',
    whyItMatters: '가설을 finding처럼 말하지 않고, 현재 가진 증거가 허용하는 만큼만 주장하게 한다.',
    checks: ['직접 재현된 것은 무엇인가?', '문헌에만 의존하는 부분은 무엇인가?', '아직 남은 가정은 무엇인가?'],
  },
  {
    id: 'common-structure',
    title: '사례에서 공통 구조 찾기',
    lessonId: '11-researchers-03',
    status: 'explore',
    summary: '취약점 이름이 달라도 반복되는 입력·신뢰·시간·상태 문제를 비교한다.',
    whyItMatters: '개별 사례 암기에서 벗어나 다른 시스템에도 던질 수 있는 질문을 만들 수 있다.',
    checks: ['공통 조건은 무엇인가?', '겉모습만 비슷한 것은 무엇인가?', '다른 범주에서도 같은 질문이 유효한가?'],
  },
  {
    id: 'research-gap',
    title: '빈칸을 질문으로 바꾸기',
    lessonId: '13-misc-03',
    status: 'explore',
    summary: '이미 알려진 사례를 표로 비교해 아직 약하게 다뤄진 조합을 찾고 반박 가능한 질문으로 만든다.',
    whyItMatters: '아이디어 생성이 막연한 브레인스토밍이 아니라 기존 지식의 구조적 빈칸에서 시작하게 된다.',
    checks: ['정말 비어 있는가, 단지 문서화가 약한가?', '왜 성립하지 않을 수도 있는가?', '가장 작은 검증은 무엇인가?'],
  },
];
