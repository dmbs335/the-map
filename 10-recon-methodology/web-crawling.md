# Web Crawling — Security Reconnaissance Methodology Taxonomy

---

## Classification Structure

이 택소노미는 웹 애플리케이션의 공격 표면을 **빠짐없이 발견하기 위한 크롤링 기법**을 구조화한다. 핵심 축은 **발견 기법**(§1–§7)이며, 각 기법이 찾아내는 대상의 종류를 교차 축으로 분류한다.

| Discovery Target | Description |
|---|---|
| **경로/엔드포인트** | URL, 라우트, 디렉토리, 파일 |
| **파라미터** | Query, Body, Header, Cookie 파라미터 |
| **API 스키마** | Operation, Type, Field, Mutation |
| **시크릿** | API 키, 토큰, 크레덴셜, 내부 URL |
| **기술 스택** | 프레임워크, 버전, 미들웨어, 서버 |

크롤링의 근본 원리: 애플리케이션은 의도적으로 노출한 기능보다 **항상 더 많은 표면**을 가진다. 배포 아티팩트, 레거시 엔드포인트, 디버그 인터페이스, 클라이언트 코드에 하드코딩된 경로 등 — 각 발견 기법은 이 숨겨진 표면의 서로 다른 영역을 드러낸다.

---

## §1. Active Spidering (링크 기반 능동 크롤링)

브라우저처럼 페이지를 방문하고 링크를 따라가며 애플리케이션의 구조를 재귀적으로 탐색하는 가장 기본적인 크롤링 방식. 발견 범위는 **실제로 링크된 콘텐츠**에 한정된다.

### §1-1. 탐색 전략 (Traversal Strategy)

| Subtype | Mechanism | Use Case |
|---|---|---|
| **Breadth-First (너비 우선)** | 같은 깊이의 모든 링크를 먼저 방문한 뒤 다음 깊이로 진행. 상위 페이지를 빠르게 커버하며 중요도 높은 페이지를 먼저 발견 | 초기 표면 매핑 — 넓은 사이트에서 전체 구조를 빠르게 파악 |
| **Depth-First (깊이 우선)** | 한 경로를 끝까지 따라간 뒤 백트래킹. 깊이 중첩된 기능(다단계 위저드, 중첩 카테고리)을 놓치지 않음 | 특정 기능 영역의 완전한 탐색 — 결제 흐름, 관리자 패널 등 |
| **Hybrid (적응형)** | BFS로 시작해 전체 구조를 파악한 뒤, 관심 영역에 DFS 적용 | 실전 크롤링의 기본 전략 — 대부분의 도구가 이 방식 지원 |

### §1-2. 렌더링 모드 (Rendering Mode)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP-Only (정적)** | HTML 소스만 파싱하여 `<a>`, `<form>`, `<link>` 등 태그에서 URL 추출. 빠르고 가벼움 | 서버 렌더링 페이지 (SSR), 레거시 애플리케이션 |
| **Headless Browser (동적)** | Puppeteer, Playwright 등으로 JavaScript를 실행하고, DOM 변화 후 생성되는 링크까지 수집. SPA 필수 | React, Angular, Vue 등 클라이언트 렌더링 앱 |
| **Hybrid Rendering** | 초기 크롤은 HTTP-Only로 빠르게 수행, JS 의존 경로 탐지 시 headless로 전환 | 규모가 큰 사이트에서 속도와 커버리지 균형 |

### §1-3. 스코프 제어 (Scope Control)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Same-Origin 제한** | 동일 origin(scheme+host+port) 내 링크만 추적 | 단일 애플리케이션 심층 분석 |
| **Same-Domain 확장** | 서브도메인 포함 (`*.example.com`) 크롤링 | 마이크로서비스 아키텍처, 서브도메인별 기능 분리된 환경 |
| **Cross-Domain 추적** | 외부 도메인 링크도 제한적으로 추적 (CDN, API 서버, 인증 서버 등) | 서드파티 통합이 많은 애플리케이션 |
| **URL 정규화 & 중복 제거** | 세션 ID, 추적 파라미터, 프래그먼트 등을 제거하여 동일 페이지 중복 방문 방지 | 무한 크롤 루프 방지 — 모든 크롤링의 필수 사항 |
| **Depth/Page Limit** | 최대 깊이, 총 페이지 수, 도메인별 상한 설정 | 리소스 제약 하 크롤링, 대규모 사이트 |

### §1-4. 폼 & 인터랙션 핸들링

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **자동 폼 제출** | `<form>` 태그 발견 시 유효한 입력값으로 자동 제출하여 결과 페이지 탐색 | Burp Crawler의 form submission 기능 |
| **Multi-Step Flow 추적** | 위저드/체크아웃처럼 여러 단계로 구성된 흐름을 순서대로 진행하며 각 단계의 경로 수집 | 상태 기반 워크플로우를 가진 애플리케이션 |
| **Event-Driven Discovery** | 클릭, 호버, 스크롤 등 DOM 이벤트를 트리거하여 동적으로 생성되는 콘텐츠 발견 | ZAP AJAX Spider, headless 기반 이벤트 크롤링 |

---

## §2. Directory & File Bruteforcing (워드리스트 기반 경로 열거)

링크가 존재하지 않는 숨겨진 경로를 워드리스트 기반으로 추측하여 발견하는 기법. Active Spidering이 **링크된 것**만 찾는다면, 브루트포스는 **링크되지 않았지만 존재하는 것**을 찾는다.

### §2-1. 기본 브루트포스

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **디렉토리 열거** | `/admin/`, `/backup/`, `/api/v1/` 등 일반적 경로명을 대입하여 200/301/403 응답 확인 | 범용 워드리스트 (raft-medium, dirb/common.txt) |
| **파일 열거** | `.bak`, `.old`, `.swp`, `.DS_Store`, `web.config`, `.env` 등 백업/설정 파일 대입 | 확장자별 워드리스트, 기술 스택에 맞는 파일명 |
| **재귀적 브루트포스** | 발견된 디렉토리 내부를 다시 브루트포스 — `/api/` 발견 → `/api/v1/`, `/api/users/`, `/api/admin/` 탐색 | feroxbuster, ffuf `-recursion` 옵션 |
| **확장자 퍼징** | 동일 경로에 `.php`, `.asp`, `.jsp`, `.json`, `.xml` 등 다양한 확장자를 붙여 시도 | 기술 스택이 불분명할 때, 또는 여러 기술이 혼재된 환경 |
| **가상 호스트 열거** | 동일 IP에 `Host: FUZZ.example.com` 헤더로 다양한 호스트명을 대입하여 숨겨진 가상 호스트 발견 (ffuf, gobuster vhost 모드) | 하나의 IP에 여러 가상 호스트가 바인딩된 환경 — 내부 관리 패널, 스테이징 등 |

### §2-2. 워드리스트 전략

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **범용 워드리스트** | SecLists, FuzzDB, OneListForAll — 언어/프레임워크 불문 일반적 경로 | 초기 탐색, 기술 스택 파악 전 |
| **기술 특화 워드리스트** | Spring Boot (`/actuator/*`), WordPress (`/wp-admin/*`), .NET (`/elmah.axd`) 등 프레임워크 고유 경로 | Wappalyzer/WhatWeb으로 기술 스택 식별 후 |
| **커스텀 워드리스트 생성** | 대상 사이트의 기존 URL 패턴에서 경로 컨벤션을 추출하여 맞춤형 리스트 생성 (CeWL, 크롤 결과 분석) | 대상 고유의 네이밍 컨벤션이 있을 때 |
| **Assetnote Wordlists** | CommonCrawl 데이터에서 추출한 실제 웹 경로 빈도 기반 워드리스트 | 대규모 크롤링 데이터 기반의 현실적 경로명 |

### §2-3. 응답 분석 & 필터링

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **상태 코드 필터** | 200(존재), 301/302(리다이렉트), 403(접근 금지 but 존재) 구분 | 기본 필터링 — 404를 제외하되, 커스텀 404 탐지 필요 |
| **응답 크기 필터** | 동일 크기 응답 대량 발생 시 커스텀 404/에러 페이지로 판단하여 제외 | ffuf `-fs` (filter size), `-fw` (filter words) |
| **응답 내용 기반 필터** | 특정 문자열("Not Found", "Error") 포함 여부로 실제 페이지 vs 에러 구분 | 커스텀 에러 페이지가 200 응답을 반환하는 경우 |
| **기술 스택 연동 퍼징** | Wappalyzer로 탐지된 기술에 맞춰 확장자와 워드리스트를 자동 선택 (ffufw) | 자동화된 기술 적응형 브루트포스 |

---

## §3. Parameter Discovery (숨겨진 파라미터 발견)

엔드포인트를 찾은 이후 — 그 엔드포인트가 처리하는 **숨겨진 파라미터**를 발견하는 단계. 클라이언트 코드에서 제거된 관리자 전용 파라미터, 디버그 플래그, 문서화되지 않은 필터 등이 대상.

### §3-1. 파라미터 브루트포스

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **GET 파라미터 퍼징** | `?debug=1`, `?admin=true`, `?format=json` 등 대량 파라미터를 대입, 응답 변화 감지 | Arjun (25,890 파라미터, ~50 요청으로 테스트), x8 (Rust 기반 고속) |
| **POST 바디 퍼징** | `{"role":"admin"}`, `{"debug":true}` 등 JSON/form 바디 파라미터 대입 | Arjun `-m POST`, x8 `-X POST` |
| **HTTP 헤더 퍼징** | `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` 등 커스텀 헤더 대입으로 숨겨진 기능 또는 접근 제어 우회 발견 | param-miner (Burp 확장), 헤더 전용 워드리스트 |
| **Cookie 파라미터 퍼징** | 쿠키 값에 추가 파라미터 삽입하여 서버 측 처리 여부 확인 | 쿠키 기반 설정/기능 전환이 있는 애플리케이션 |

### §3-2. 응답 변화 탐지

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **상태 코드 변화** | 특정 파라미터 추가 시 응답 코드 변경 (200→403, 200→500 등) — 파라미터가 처리되고 있음을 의미 | 가장 명확한 신호 |
| **응답 크기 변화** | 바디 크기가 유의미하게 달라짐 — 추가 데이터가 반환되거나 에러 메시지가 변경됨 | 노이즈 제거를 위한 baseline 응답 크기 기록 필요 |
| **응답 시간 변화** | 특정 파라미터가 DB 쿼리나 외부 호출을 트리거하여 응답 시간이 증가 | 타이밍 기반 블라인드 탐지 |
| **리플렉션 탐지** | 파라미터 값이 응답에 반영(reflected)됨 — XSS, SSTI, 헤더 인젝션 가능성 | 입력값이 어디에 반영되는지 추적 |

### §3-3. 수동 파라미터 마이닝

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **웹 아카이브 파라미터 추출** | ParamSpider — Wayback Machine에서 대상 도메인의 과거 URL을 수집하여 파라미터명 추출 | 과거에 존재했던 파라미터가 서버에서 아직 처리될 수 있음 |
| **HTML 소스 파라미터 추출** | 주석, hidden 폼 필드, disabled 입력, data-* 속성에서 파라미터명 수집 | 클라이언트에서 제거됐지만 서버에서 처리되는 파라미터 |
| **JS 소스 파라미터 추출** | JavaScript 코드 내 fetch/XHR 호출의 파라미터, JSON 키, 설정 객체 분석 | §4 JavaScript 분석과 연계 |

---

## §4. JavaScript Analysis (클라이언트 코드 분석)

현대 웹 애플리케이션의 핵심 공격 표면은 **JavaScript 소스 코드**에 노출된다. API 엔드포인트, 인증 토큰, 내부 URL, 라우팅 규칙, 디버그 기능 등이 클라이언트에 번들링되어 전송된다.

### §4-1. 엔드포인트 추출 (Endpoint Extraction)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **정규식 기반 URL 추출** | LinkFinder — JS 파일에서 URL/경로 패턴을 정규식으로 매칭하여 추출 | 빠르지만 false positive 존재, 초기 스캔에 적합 |
| **AST 기반 정밀 추출** | jsluice — go-tree-sitter로 AST를 파싱하여 `fetch()`, `XMLHttpRequest`, `window.open()`, `document.location` 등 URL이 실제로 사용되는 컨텍스트만 추출 | 정규식 대비 정확도 높음, false positive 감소 |
| **Burp 수동 수집** | JSpector — 프록시를 통과하는 JS 파일을 수동으로 분석, 발견된 엔드포인트를 Burp issue로 자동 등록 | 실시간 트래픽 분석 중 JS 엔드포인트 자동 탐지 |
| **번들 분석 (Source Map)** | `.js.map` 파일이 존재하면 원본 소스 구조 복원 가능 — 컴포넌트별 API 호출, 라우트 정의 등 명확히 파악 | 프로덕션에 소스맵이 노출된 경우 (빈번함) |

### §4-2. 시크릿 추출 (Secret Extraction)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **API 키 / 토큰** | SecretFinder — 정규식으로 API 키 패턴 (`AIza...`, `sk-...`, `ghp_...`), JWT, Bearer 토큰 등 탐지 | 클라이언트 JS에 하드코딩된 인증 정보 |
| **내부 URL / 엔드포인트** | 스테이징 서버 (`staging.internal.example.com`), 내부 API (`http://10.0.0.x/api`) 등 비공개 URL 노출 | 개발 환경 URL이 프로덕션 빌드에 남아있는 경우 |
| **설정 객체** | `window.__CONFIG__`, `window.__INITIAL_STATE__` 등 글로벌 변수에 노출된 기능 플래그, 환경 변수, 서비스 URL | SPA의 초기 상태 전달 패턴 |
| **주석 내 정보** | 개발자 주석에 남긴 TODO, FIXME, 내부 설명, 비활성화된 기능 참조 | 미니파이 전 JS 또는 소스맵에서 추출 |

### §4-3. 라우트 & 접근 제어 분석

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SPA 라우트 추출** | React Router, Vue Router, Angular Router 설정에서 전체 라우트 맵 추출 — 관리자 전용 경로, 숨겨진 페이지 포함 | 프레임워크별 라우터 설정 패턴 인식 |
| **Role 기반 경로 발견** | 클라이언트 측 접근 제어 로직 (`if (user.role === 'admin')`) 에서 관리자 전용 엔드포인트/기능 식별 | 클라이언트에서 권한 체크하는 SPA |
| **비활성 기능 탐지** | 기능 플래그로 비활성화된 코드 경로가 JS에 여전히 포함 — 서버 측 엔드포인트는 활성 상태일 수 있음 | Feature flag 기반 개발, 점진적 롤아웃 |

### §4-4. 히스토리컬 JS 분석

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **아카이브 JS 비교** | Wayback Machine에서 과거 버전의 JS 파일을 수집하여 현재 버전과 diff — 제거된 엔드포인트, 변경된 API 경로, 삭제된 시크릿 발견 | waymore로 과거 JS 파일 다운로드 |
| **Git 히스토리 JS 분석** | 공개 `.git` 디렉토리 또는 GitHub 리포에서 JS 변경 이력 추적 — 커밋에서 제거된 API 키, 엔드포인트 | `.git` 디렉토리 노출 또는 소스 리포 접근 가능 |

---

## §5. API Surface Discovery (API 스키마 열거)

REST, GraphQL, SOAP, WebSocket 등 API 인터페이스의 전체 스키마를 발견하는 기법. 웹 UI 크롤링만으로는 API의 일부만 보이며, 스키마 열거를 통해 문서화되지 않은 operation, field, type을 발견할 수 있다.

### §5-1. REST / OpenAPI Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Swagger/OpenAPI 파일 탐색** | `/swagger.json`, `/openapi.yaml`, `/api-docs`, `/v2/api-docs`, `/swagger-ui.html` 등 알려진 경로 브루트포스 | 개발자가 문서 엔드포인트를 비활성화하지 않은 경우 |
| **API 버전 열거** | `/api/v1/`, `/api/v2/`, `/api/v3/` — 이전 버전에 더 느슨한 인증/검증이 남아있을 수 있음 | 여러 API 버전이 병행 운영되는 환경 |
| **HTTP 메서드 퍼징** | 동일 엔드포인트에 GET, POST, PUT, DELETE, PATCH, OPTIONS 등 다양한 메서드 대입 — 문서화되지 않은 operation 발견 | `OPTIONS` 응답의 `Allow` 헤더, 또는 405 vs 200 응답 차이 |
| **Content-Type 전환** | 동일 엔드포인트에 `application/json`, `application/xml`, `application/x-www-form-urlencoded` 등 다양한 형식으로 요청 — 파서 차이로 추가 공격 표면 노출 | 서버가 여러 Content-Type을 수용하는 경우 |

### §5-2. GraphQL Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Introspection 쿼리** | `{__schema{types{name,fields{name}}}}` — 전체 스키마(타입, 필드, 뮤테이션, 쿼리) 일괄 추출 | Introspection이 활성화된 경우 (프로덕션에서도 빈번) |
| **Introspection 우회** | `__schema` 뒤에 특수문자 삽입, GET 대신 POST, `query` 대신 다른 파라미터명 사용 등으로 제한 우회 | 정규식 기반 introspection 차단을 우회 |
| **Field Suggestion 기반 복원** | Introspection 비활성 시, 잘못된 필드명을 보내면 에러 메시지에 유사한 필드명 제안 — 이를 반복하여 스키마 재구성 | InQL, Clairvoyance — 에러 기반 스키마 추론 |
| **엔드포인트 탐색** | `/graphql`, `/gql`, `/graphiql`, `/playground`, `/v1/graphql` 등 브루트포스 | GraphQL 엔드포인트 경로가 표준이 아닌 경우 |

### §5-3. SOAP / WSDL Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WSDL 파일 탐색** | `?wsdl`, `?WSDL`, `/service.wsdl`, `/application.wadl` 등 경로 탐색 | SOAP 서비스가 WSDL을 노출한 경우 |
| **Operation 열거** | WSDL에서 operation 목록 추출 후 각 operation을 개별 호출하여 접근 제어 테스트 | WSDL이 모든 operation을 포함하지만 일부만 인증 필요 |

### §5-4. WebSocket Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WS 엔드포인트 탐색** | `/ws`, `/socket`, `/realtime`, JS 코드 내 `new WebSocket()` 호출에서 URL 추출 | 실시간 기능 (채팅, 알림, 대시보드) |
| **메시지 포맷 분석** | 연결 후 전송되는 메시지 구조 분석 — JSON-RPC, Protocol Buffers, 커스텀 프로토콜 | WS 트래픽 캡처 (Burp WebSocket history) |

---

## §6. Passive & Historical Collection (비접촉 수집)

대상 서버에 직접 요청을 보내지 않고(또는 최소한의 요청으로) 공격 표면 정보를 수집하는 기법. 탐지 위험 제로, 삭제된 콘텐츠 복원 가능.

### §6-1. 웹 아카이브

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Wayback Machine URL 수집** | waybackurls, gau, waymore — Wayback CDX API에서 대상 도메인의 과거 URL 전체 목록 추출 | 아카이브에 캡처된 이력이 있는 도메인 |
| **CommonCrawl 데이터** | CommonCrawl 인덱스에서 대상 도메인 관련 URL 및 응답 데이터 추출 | gau가 CommonCrawl 포함 자동 검색 |
| **과거 응답 다운로드** | waymore — Wayback, CommonCrawl 등 다중 소스에서 URL뿐 아니라 실제 과거 응답(HTML, JS, JSON)까지 다운로드하여 삭제된 콘텐츠 복원 | 삭제된 페이지, 제거된 API 응답 확인 |
| **변경 이력 비교** | 같은 URL의 시간대별 스냅샷을 비교하여 추가/제거된 기능, 엔드포인트, 시크릿 탐지 | 시계열 diff 분석 |

### §6-2. 검색 엔진 & 인덱스

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Google Dorking** | `site:example.com filetype:pdf`, `site:example.com inurl:admin`, `site:example.com ext:sql` 등 고급 연산자로 인덱싱된 민감 콘텐츠 발견 | Google이 크롤링한 콘텐츠가 있는 경우 |
| **GitHub/GitLab 검색** | `"example.com" password`, `"example.com" api_key` — 퍼블릭 리포에서 대상 관련 코드, 크레덴셜, 내부 URL 검색 | 개발자가 실수로 커밋한 시크릿 |
| **Shodan / Censys** | IP 기반 서비스 열거 — 열린 포트, 서비스 배너, SSL 인증서 정보, HTTP 응답 헤더 | 인터넷에 노출된 서비스 전체 파악 |
| **URLScan.io** | 다른 사용자가 스캔한 결과에서 대상 도메인의 URL, 리소스, 리다이렉트 체인 수집 | 제3자가 이미 스캔한 이력이 있는 경우 |

### §6-3. 인증서 투명성 (Certificate Transparency)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **crt.sh 서브도메인 열거** | CT 로그에서 대상 도메인의 SSL 인증서 이력 조회 — 서브도메인, 내부 호스트명, 와일드카드 패턴 발견 | HTTPS를 사용하는 모든 도메인 |
| **내부 호스트명 노출** | `staging.internal.example.com`, `jenkins.corp.example.com` 등 내부용 서브도메인이 인증서에 포함 | 내부 서비스에 대해 공인 인증서를 발급한 경우 |

### §6-4. 메타파일 분석

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **robots.txt** | `Disallow` 항목에서 숨기려는 경로 목록 추출 — `/admin/`, `/internal/`, `/api/debug/` 등 | 보안이 아닌 크롤러 제어 목적으로 경로를 나열한 경우 |
| **sitemap.xml** | 전체 URL 구조를 체계적으로 나열한 파일 — robots.txt에서 참조 위치 확인 | 사이트맵이 공개된 경우 |
| **security.txt** | `/.well-known/security.txt` — 보안 연락처, 정책 범위, 선호 언어 등 | 버그바운티/VDP 프로그램 정보 |
| **humans.txt, crossdomain.xml** | 개발팀 정보, Flash/Silverlight 크로스도메인 정책 등 추가 메타정보 | 레거시 설정 파일이 남아있는 경우 |

---

## §7. Authenticated Crawling (인증 기반 크롤링)

로그인 벽 뒤에 숨겨진 기능은 인증된 상태에서 크롤링해야만 발견된다. 권한 수준(일반 사용자, 관리자, API 클라이언트)에 따라 노출되는 표면이 달라지므로, **다중 역할 크롤링**이 핵심이다.

### §7-1. 세션 획득 & 유지

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **폼 기반 로그인** | 크롤러가 로그인 폼을 자동 인식하고 크레덴셜을 제출하여 세션 쿠키 획득 | Burp Crawler login configuration, ZAP authentication context |
| **토큰 기반 인증** | Bearer 토큰, JWT, API 키를 요청 헤더에 주입 — 쿠키 없이 API 크롤링 | ZAP/Burp의 세션 핸들링 룰에서 토큰 자동 갱신 |
| **OAuth 플로우 자동화** | Headless 브라우저로 OAuth 인증 흐름을 완료하고, access token을 추출하여 HTTP 클라이언트에서 재사용 | OAuth 기반 인증 (Google, GitHub 등) |
| **쿠키 이식 (Cookie Transplant)** | 수동으로 브라우저에서 로그인 후, 쿠키를 추출하여 크롤러에 주입 | 2FA, CAPTCHA 등으로 자동 로그인이 어려운 경우 |
| **세션 만료 감지 & 재인증** | 크롤 중 세션 만료 탐지 (302 to login, 401 응답) 시 자동 재인증 | 장시간 크롤링, 짧은 세션 타임아웃 |

### §7-2. 다중 역할 크롤링

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **미인증 → 인증 비교** | 동일 엔드포인트에 미인증/인증 상태로 각각 크롤링하여 차이 비교 — 인증 후에만 보이는 링크, 기능, 파라미터 식별 | 권한 상승 테스트의 기초 데이터 |
| **역할별 크롤링** | 일반 사용자, 편집자, 관리자 등 각 역할로 크롤링하여 역할별 고유 기능과 엔드포인트 매핑 | Burp Crawler의 multiple login 기능 |
| **권한 매트릭스 생성** | 모든 역할의 크롤 결과를 합산하여 엔드포인트 × 역할 접근 매트릭스 구성 → IDOR, 수평/수직 권한 상승 테스트 기반 | Autorize (Burp 확장) 등과 연계 |

### §7-3. Mobile API 크롤링

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **모바일 User-Agent** | 크롤러의 UA를 모바일 디바이스로 변경하여 모바일 전용 엔드포인트, 경량 API, 다른 응답 포맷 발견 | 모바일 앱용 별도 API가 존재하는 서비스 |
| **앱 트래픽 캡처** | 모바일 앱의 프록시 트래픽을 캡처하여 API 엔드포인트, 파라미터, 인증 흐름 수집 | 앱 바이너리 분석 없이 API 표면 파악 |

---

## Crawling Pipeline — 추천 실행 순서

```
Phase 1: Passive Collection (§6)
  ├─ crt.sh 서브도메인 열거
  ├─ Wayback/gau URL 수집
  ├─ Google Dorking
  ├─ robots.txt / sitemap.xml
  └─ GitHub 시크릿 검색
      ↓
Phase 2: Active Surface Mapping (§1 + §2)
  ├─ Headless spider (BFS) → 전체 구조 파악
  ├─ 기술 스택 식별 (Wappalyzer)
  ├─ 기술 특화 워드리스트로 디렉토리 브루트포스
  └─ 재귀적 브루트포스 → 깊은 경로
      ↓
Phase 3: Client Code Analysis (§4)
  ├─ JS 파일 수집 (크롤 결과 + 아카이브)
  ├─ jsluice/LinkFinder → 엔드포인트 추출
  ├─ SecretFinder → 시크릿 탐지
  └─ SPA 라우트 분석
      ↓
Phase 4: API Schema Enumeration (§5)
  ├─ Swagger/OpenAPI 탐색
  ├─ GraphQL introspection / field suggestion
  ├─ HTTP 메서드 & Content-Type 퍼징
  └─ WebSocket 엔드포인트 분석
      ↓
Phase 5: Authenticated Deep Crawl (§7)
  ├─ 역할별 인증 크롤링
  ├─ 미인증 vs 인증 비교
  ├─ 모바일 API 크롤링
  └─ 권한 매트릭스 생성
      ↓
Phase 6: Parameter Mining (§3)
  ├─ 발견된 엔드포인트별 파라미터 브루트포스
  ├─ 아카이브 파라미터 추출 (ParamSpider)
  └─ 응답 변화 분석
```

---

## Tool Matrix

### Active Crawling (§1)

| Tool | Type | Core Capability |
|---|---|---|
| **Burp Crawler** | Commercial | 자동 로그인, 폼 제출, 세션 핸들링 통합 크롤러. 다중 역할 지원 |
| **ZAP Spider + AJAX Spider** | Open Source | 전통적 크롤러 + headless 브라우저 기반 JS 렌더링 크롤러 |
| **Katana** (ProjectDiscovery) | Open Source | Go 기반 고속 크롤러. headless/headful 모드, 스코프 제어, 파이프라인 연동 |
| **GoSpider** | Open Source | Go 기반 빠른 크롤러. sitemap 파싱, 외부 소스 연동 |
| **hakrawler** | Open Source | stdin 입력 기반 경량 크롤러. 파이프라인 조합에 최적화 |
| **Crawlee** (Apify) | Open Source | Node.js 프레임워크. Puppeteer/Playwright/Cheerio 백엔드 선택 가능 |

### Directory Bruteforcing (§2)

| Tool | Type | Core Capability |
|---|---|---|
| **feroxbuster** | Open Source | Rust 기반 고속 재귀적 콘텐츠 탐색. 자동 필터링, 확장자 퍼징 |
| **ffuf** | Open Source | Go 기반 범용 퍼저. 디렉토리, 파라미터, 가상 호스트 퍼징. 강력한 필터링 |
| **dirsearch** | Open Source | Python 기반. 확장자 조합, 재귀 탐색, 다양한 워드리스트 지원 |
| **gobuster** | Open Source | Go 기반 경량. 디렉토리, DNS, 가상 호스트 모드 |

### Parameter Discovery (§3)

| Tool | Type | Core Capability |
|---|---|---|
| **Arjun** | Open Source | 25,890 파라미터 사전, ~50 요청으로 테스트. GET/POST/JSON 지원 |
| **x8** | Open Source | Rust 기반 고속. 커스텀 워드리스트, 헤더/쿠키 파라미터 지원 |
| **param-miner** | Open Source (Burp) | Burp 확장. 헤더, 쿠키, URL 파라미터 자동 탐지 |
| **ParamSpider** | Open Source | Wayback에서 과거 파라미터 추출. 수동 소스 기반 |

### JavaScript Analysis (§4)

| Tool | Type | Core Capability |
|---|---|---|
| **jsluice** (BishopFox) | Open Source | AST 기반 정밀 URL/시크릿 추출. go-tree-sitter 기반 |
| **LinkFinder** | Open Source | 정규식 기반 JS 엔드포인트 추출. HTML 리포트 생성 |
| **SecretFinder** | Open Source | JS 내 API 키, 토큰, 크레덴셜 패턴 매칭 |
| **JSpector** | Open Source (Burp) | Burp 확장. 프록시 통과 JS 자동 분석, issue 자동 등록 |

### API Discovery (§5)

| Tool | Type | Core Capability |
|---|---|---|
| **InQL** | Open Source (Burp) | GraphQL introspection, field suggestion 기반 스키마 복원, 쿼리 생성 |
| **Clairvoyance** | Open Source | Introspection 비활성 시 에러 피드백 기반 GraphQL 스키마 재구성 |
| **sj** (Swagger Jacker) | Open Source | Swagger/OpenAPI 파일에서 엔드포인트 추출 및 인증 테스트 자동화 |
| **Postman/Hoppscotch** | Open Source | OpenAPI/GraphQL 스키마 임포트 후 수동 API 탐색 및 테스트 |

### Passive Collection (§6)

| Tool | Type | Core Capability |
|---|---|---|
| **gau** | Open Source | Wayback, CommonCrawl, URLScan, VirusTotal에서 URL 일괄 수집 |
| **waymore** (xnl-h4ck3r) | Open Source | Wayback, CommonCrawl, URLScan 등 다중 소스에서 URL + 과거 응답까지 다운로드. 필터링 옵션 강화 |
| **waybackurls** | Open Source | Wayback Machine 전용 빠른 URL 추출 |
| **crt.sh** | Web Service | Certificate Transparency 로그 기반 서브도메인 열거 |

---

## Core Principles

**1. 단일 기법에 의존하지 않는다.** Active Spidering은 링크된 콘텐츠만, Bruteforcing은 추측 가능한 경로만, JS 분석은 클라이언트에 포함된 정보만 찾는다. 각 기법은 서로 다른 영역을 커버하며, 최대 커버리지는 **모든 기법의 합집합**에서 나온다.

**2. 수동(Passive)으로 시작한다.** 대상에 단 하나의 요청도 보내기 전에, 아카이브와 공개 소스에서 수집할 수 있는 정보를 먼저 확보한다. 이는 탐지 없이 공격 표면의 상당 부분을 파악할 수 있게 하며, 이후 능동 크롤링의 방향을 잡아준다.

**3. 기술 스택에 맞춰 조정한다.** Spring Boot 앱에는 `/actuator/*` 워드리스트를, GraphQL 서비스에는 introspection을, SPA에는 headless 렌더링을 적용한다. 범용적 크롤링은 기본이지만, **기술 특화 크롤링이 고유한 표면을 드러낸다.**

**4. 시간 축을 활용한다.** 현재 라이브 상태뿐 아니라 과거 상태(Wayback), 소스 이력(Git), API 버전 이력을 분석한다. 제거된 엔드포인트와 시크릿은 서버에서 여전히 작동할 수 있다.

**5. 역할을 전환한다.** 동일 애플리케이션도 미인증, 일반 사용자, 관리자, API 클라이언트, 모바일 앱 관점에서 각각 다른 공격 표면을 노출한다. 다중 역할 크롤링은 IDOR와 권한 상승 취약점의 기초 데이터를 제공한다.

---

## References

- OWASP. "Web Security Testing Guide — Information Gathering." OWASP WSTG Latest.
- OWASP. "API Reconnaissance." OWASP WSTG Latest.
- YesWeHack. "Discover & Map Hidden Endpoints & Parameters." YesWeHack Learn.
- YesWeHack. "Parameter Discovery Quick Guide." YesWeHack Learn.
- YesWeHack. "Harnessing Wayback Machine for Bug Bounty." YesWeHack Learn.
- Intigriti. "7 Overlooked Recon Techniques to Find More Vulnerabilities." Intigriti Blog.
- Intigriti. "Finding Hidden Input Parameters: Advanced Enumeration Guide." Intigriti Blog.
- PortSwigger. "Crawling — Burp Suite Documentation." PortSwigger Docs.
- PortSwigger. "Crawling with Multiple Logins." PortSwigger Blog.
- PortSwigger. "API Testing." Web Security Academy.
- ProjectDiscovery. "Building a Fast One-Shot Recon Script." ProjectDiscovery Blog.
- BishopFox. "jsluice: Extract URLs, paths, secrets from JavaScript." GitHub.
- HackTricks. "Web API Pentesting." HackTricks Wiki.
- HackTricks. "GraphQL." HackTricks Wiki.
- kpwn.de. "JavaScript Analysis for Pentesters." 2023.
- SwissKyRepo. "PayloadsAllTheThings — Hidden Parameters." GitHub.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
