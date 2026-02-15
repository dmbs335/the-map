# Spring Framework Mass Assignment 보안 분석 예제

> 이 문서는 framework-source-security-analyzer 스킬의 출력 예제입니다.
> 실제 분석 시 참고할 형식을 보여줍니다.

---

# Spring MVC DataBinder 소스코드 보안 분석: Mass Assignment 메타 구조

> **분석 대상**: Spring Framework 6.1.x, Spring MVC
> **소스 조사**: github.com/spring-projects/spring-framework
> **분석 시점**: 2025년 2월
> **주요 CVE 반영**: CVE-2022-22965 (Spring4Shell), CVE-2022-22950

---

## Executive Summary

Spring MVC의 DataBinder는 HTTP 요청 파라미터를 자동으로 Java 객체 필드에 바인딩하는 편의 기능을 제공한다. 이 "Convention over Configuration" 철학은 개발 속도를 높이지만, 개발자가 명시적으로 제한하지 않는 한 **모든 public setter에 대한 쓰기 권한**을 HTTP 클라이언트에게 암묵적으로 부여한다. 

핵심 문제는 프레임워크가 "편의성"을 위해 **기본적으로 모든 것을 허용(allow-by-default)**하며, 보안은 개발자의 명시적 거부(explicit deny)에 의존한다는 점이다. 이는 Mass Assignment 취약점의 구조적 원인이다.

---

## 제1부: 설계 철학과 보안 트레이드오프

### 1. Convention over Configuration의 함정 ([WebDataBinder.java](https://github.com/spring-projects/spring-framework/blob/main/spring-web/src/main/java/org/springframework/web/bind/WebDataBinder.java))

**설계 철학**: 
Spring은 개발자가 명시적 설정 없이도 빠르게 애플리케이션을 구축할 수 있도록 "관례"를 제공한다. `@ModelAttribute`를 사용하면 request parameter가 자동으로 객체에 매핑된다.

**구현 메커니즘**:
```java
// WebDataBinder.java (lines 200-250, simplified)
public class WebDataBinder extends DataBinder {
    
    public void bind(ServletRequest request) {
        MutablePropertyValues mpvs = new ServletRequestParameterPropertyValues(request);
        doBind(mpvs);  // 실제 바인딩 수행
    }
    
    protected void doBind(MutablePropertyValues mpvs) {
        checkAllowedFields(mpvs);   // allowedFields 체크
        checkRequiredFields(mpvs);  // requiredFields 체크
        applyPropertyValues(mpvs);  // 여기서 실제로 setter 호출
    }
    
    protected void checkAllowedFields(MutablePropertyValues mpvs) {
        PropertyValue[] pvs = mpvs.getPropertyValues();
        for (PropertyValue pv : pvs) {
            String field = PropertyAccessorUtils.canonicalPropertyName(pv.getName());
            if (!isAllowed(field)) {  // allowedFields가 null이면 모두 허용!
                mpvs.removePropertyValue(pv);
            }
        }
    }
    
    protected boolean isAllowed(String field) {
        String[] allowed = getAllowedFields();
        // allowed가 null이면 모든 필드 허용 (기본값)
        if (allowed == null) {
            return true;  // 이것이 문제의 근원
        }
        // ... pattern matching
    }
}
```

**보안 함의**: 
- `allowedFields`의 기본값은 `null` → 모든 필드 허용
- `disallowedFields`는 블랙리스트 방식 → 우회 가능
- 개발자가 **명시적으로 제한하지 않으면** 모든 setter가 노출됨

**공격 벡터**:
```java
// 취약한 컨트롤러
@PostMapping("/user/update")
public String updateUser(@ModelAttribute User user) {
    userRepository.save(user);  // 모든 필드가 바인딩됨!
    return "success";
}

// User.java
public class User {
    private String name;
    private String email;
    private boolean isAdmin;  // 개발자가 이 필드를 노출할 의도가 없었음
    
    // getters and setters for all fields
}
```

**공격 페이로드**:
```http
POST /user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=Alice&email=alice@example.com&isAdmin=true
```

→ `user.setAdmin(true)`가 자동으로 호출되어 권한 상승

**실제 사례**: 
- GitHub Security Advisory: Spring MVC mass assignment (여러 건)
- 실무에서 매우 흔한 취약점 패턴

**근본 원인 분석**:
- **왜 이렇게 설계되었는가**: 개발 속도와 편의성 우선. 간단한 CRUD 앱에서는 모든 필드를 바인딩하는 것이 편리함.
- **대안은 무엇이었는가**: 명시적 화이트리스트를 기본으로 (Spring이 선택하지 않은 길)
- **왜 이 대안을 선택하지 않았는가**: 개발자 경험(DX) 저하. 모든 필드를 명시적으로 나열해야 함.

**완화 방법**:

**방법 1: @InitBinder로 allowedFields 화이트리스트 설정**
```java
@Controller
public class UserController {
    
    @InitBinder("user")  // "user"라는 이름의 ModelAttribute에만 적용
    public void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("name", "email");  // 화이트리스트
        // isAdmin은 바인딩되지 않음
    }
    
    @PostMapping("/user/update")
    public String updateUser(@ModelAttribute("user") User user) {
        userRepository.save(user);
        return "success";
    }
}
```

**방법 2: DTO 분리 (권장)**
```java
// UserUpdateDTO.java - 요청 전용 DTO
public class UserUpdateDTO {
    private String name;
    private String email;
    // isAdmin 필드 없음
    
    // getters and setters
}

@PostMapping("/user/update")
public String updateUser(@ModelAttribute UserUpdateDTO dto) {
    User user = userRepository.findById(currentUserId);
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    // isAdmin은 명시적으로 설정되지 않음
    userRepository.save(user);
    return "success";
}
```

**방법 3: @JsonView 사용 (REST API)**
```java
public class User {
    public interface PublicView {}
    public interface AdminView extends PublicView {}
    
    @JsonView(PublicView.class)
    private String name;
    
    @JsonView(PublicView.class)
    private String email;
    
    @JsonView(AdminView.class)  // Admin만 설정 가능
    private boolean isAdmin;
}

@PostMapping("/user/update")
@JsonView(User.PublicView.class)  // PublicView만 허용
public User updateUser(@RequestBody User user) {
    // isAdmin은 바인딩되지 않음
    return userRepository.save(user);
}
```

---

### 2. @ModelAttribute의 암묵적 신뢰 경계 ([ModelAttributeMethodProcessor.java](https://github.com/spring-projects/spring-framework/blob/main/spring-webmvc/src/main/java/org/springframework/web/servlet/mvc/method/annotation/ModelAttributeMethodProcessor.java))

**설계 철학**:
`@ModelAttribute`는 HTTP 요청을 신뢰할 수 있는 데이터로 간주하고 자동 변환한다.

**구현 메커니즘**:
```java
// ModelAttributeMethodProcessor.java
public final Object resolveArgument(MethodParameter parameter, ...) {
    String name = ModelFactory.getNameForParameter(parameter);
    Object attribute = createAttribute(name, parameter, ...);  // 객체 생성
    
    WebDataBinder binder = binderFactory.createBinder(request, attribute, name);
    bindRequestParameters(binder, request);  // 자동 바인딩
    
    return attribute;  // 컨트롤러에 전달
}

protected void bindRequestParameters(WebDataBinder binder, NativeWebRequest request) {
    ServletRequest servletRequest = request.getNativeRequest(ServletRequest.class);
    ServletRequestDataBinder servletBinder = (ServletRequestDataBinder) binder;
    servletBinder.bind(servletRequest);  // WebDataBinder.bind() 호출
}
```

**보안 함의**:
- Request parameter → Trusted object로의 자동 승격
- 개발자는 "이미 검증된 객체"를 받는다고 착각할 수 있음
- 실제로는 **HTTP 클라이언트가 통제하는 데이터**

**공격 벡터**: (동일하게 Mass Assignment)

---

### 3. Spring4Shell (CVE-2022-22965): Class.classLoader 접근 ([WebDataBinder.java](https://github.com/spring-projects/spring-framework/blob/main/spring-web/src/main/java/org/springframework/web/bind/WebDataBinder.java))

**배경**:
Spring 5.3.17 이전, Java 9+ 환경에서 `class.classLoader` 속성에 접근 가능했던 구조적 설계 문제.

**구현 메커니즘** (취약 버전):
```java
// BeanWrapperImpl.java (PropertyAccessor 구현체)
public void setPropertyValue(String propertyName, Object value) {
    // "class.module.classLoader.resources.context.parent.pipeline.first..."
    // 이런 중첩 속성 접근을 허용
    PropertyTokenHolder tokens = getPropertyNameTokens(propertyName);
    setPropertyValue(tokens, new PropertyValue(propertyName, value));
}
```

DataBinder는 기본적으로 `class` 필드를 `disallowedFields`에 포함하지 **않았음** (Java 8 시대 설계).

**보안 함의**:
- Java 9+에서 `class.getModule()` 접근 가능
- `class.module.classLoader`를 통해 Tomcat 내부 접근
- Tomcat의 `AccessLogValve` 설정을 덮어써서 webshell 생성

**공격 페이로드** (단순화):
```http
POST /user/update HTTP/1.1

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{...}
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
```

→ `shell.jsp` 웹쉘 생성 (RCE)

**실제 사례**: 
- CVE-2022-22965 (Spring4Shell)
- 2022년 3월 공개, 대규모 영향

**패치**:
```java
// Spring Framework 5.3.18+
public class WebDataBinder extends DataBinder {
    
    private static final Set<String> disallowedFields = new HashSet<>(
        Arrays.asList("class.*", "Class.*", "*.class.*", "*.Class.*")
    );
    
    @Override
    public void setDisallowedFields(@Nullable String... disallowedFields) {
        // 기본 disallowedFields에 class 관련 패턴 포함
    }
}
```

**근본 원인 분석**:
- **왜 이런 취약점이 가능했는가**: 
  1. DataBinder가 중첩 속성 접근 허용 (편의성)
  2. `disallowedFields`에 `class`가 기본 포함되지 않음 (Java 8 시절엔 문제 없었음)
  3. Java 9+ 모듈 시스템으로 새로운 공격 경로 생김
- **대안**: 
  1. 중첩 속성 깊이 제한
  2. 화이트리스트 기본 채택
  3. Reflection 기반 접근 원천 차단
- **왜 대안을 선택하지 않았는가**: 기존 애플리케이션과의 호환성 (Breaking change)

---

## 제2부: 소스코드 레벨 완화 메커니즘

### 4. DisallowedFields vs AllowedFields ([DataBinder.java](https://github.com/spring-projects/spring-framework/blob/main/spring-beans/src/main/java/org/springframework/validation/DataBinder.java))

**구현**:
```java
// DataBinder.java
public class DataBinder implements PropertyEditorRegistry, TypeConverter {
    
    @Nullable
    private String[] allowedFields;  // 화이트리스트
    
    @Nullable
    private String[] disallowedFields;  // 블랙리스트
    
    protected boolean isAllowed(String field) {
        // allowedFields가 설정되어 있으면 화이트리스트 모드
        if (this.allowedFields != null) {
            return PatternMatchUtils.simpleMatch(this.allowedFields, field);
        }
        // allowedFields가 없으면 disallowedFields 체크 (블랙리스트)
        else if (this.disallowedFields != null) {
            return !PatternMatchUtils.simpleMatch(this.disallowedFields, field);
        }
        // 둘 다 없으면 모두 허용 (기본값)
        return true;
    }
}
```

**보안 함의**:
- **allowedFields 우선**: 설정 시 화이트리스트 모드 (안전)
- **disallowedFields만**: 블랙리스트 모드 (우회 가능)
- **둘 다 없음**: 모두 허용 (취약)

**권장 사항**: 항상 `allowedFields` 사용

---

## 제3부: 언어 레벨 기여 요소

### 5. Java Reflection의 무제한 접근

**Java의 Reflection API**:
```java
// PropertyUtils (Spring 내부)
Method setter = clazz.getMethod("set" + capitalize(fieldName), paramType);
setter.invoke(object, value);  // 모든 public setter 호출 가능
```

**보안 함의**:
- Java는 public 메소드에 대한 reflection 접근을 막지 않음
- Framework가 제한하지 않으면 모든 public API가 노출됨
- 언어 레벨에서는 "public = 외부 접근 가능"이라고 가정

---

## 제4부: 최신 CVE 및 실제 공격 사례

| CVE | 연도 | 근본 원인 | 영향받는 버전 | 메타 패턴 |
|-----|------|----------|--------------|----------|
| CVE-2022-22965 | 2022 | class.classLoader 접근 허용 | 5.3.0-5.3.17 | Convention over Configuration |
| CVE-2022-22950 | 2022 | SpEL injection in DataBinder | 5.3.0-5.3.15 | Implicit Trust |

---

## 부록 A: 메타 패턴 ↔ 공격 ↔ 방어 매핑표

| 메타 패턴 | 대표 취약점 | 공격 기법 | 소스 위치 | 완화 방법 |
|----------|------------|----------|----------|----------|
| Convention over Configuration | Mass Assignment | isAdmin=true 파라미터 추가 | WebDataBinder.java:checkAllowedFields() | @InitBinder로 allowedFields 설정 |
| Implicit Trust | 권한 상승 | 의도하지 않은 필드 수정 | ModelAttributeMethodProcessor.java | DTO 분리 |
| Reflection 무제한 접근 | Class.classLoader 접근 | Spring4Shell | BeanWrapperImpl.java | disallowedFields에 "class.*" 추가 |

---

## 부록 B: 소스코드 보안 체크리스트

**설정 검증**
- [ ] 모든 `@ModelAttribute` 사용 시 `@InitBinder`로 allowedFields 설정
- [ ] allowedFields는 화이트리스트 방식 (disallowedFields 사용 금지)
- [ ] Spring Boot Actuator가 프로덕션에서 제한되었는지 확인

**코드 패턴 검증**
- [ ] Entity 직접 바인딩 대신 DTO 사용
- [ ] `@JsonView`로 직렬화 필드 제한 (REST API)
- [ ] 중요 필드(isAdmin, role 등)는 setter를 private으로 하거나 제거

**의존성 검증**
- [ ] Spring Framework 5.3.18+ 또는 6.0+ 사용 (Spring4Shell 패치)
- [ ] Spring Security 활성화 및 최신 버전 사용

---

## 부록 C: 안전한 코드 패턴 예제

### 패턴 1: DTO 사용 (권장)

```java
// UserUpdateRequest.java - 요청 전용 DTO
public class UserUpdateRequest {
    @NotBlank
    private String name;
    
    @Email
    private String email;
    
    // isAdmin 필드 없음 - 바인딩 불가능
    
    // getters and setters
}

// UserController.java
@PostMapping("/user/update")
public ResponseEntity<User> updateUser(
    @Valid @RequestBody UserUpdateRequest request,  // DTO 사용
    @AuthenticationPrincipal User currentUser
) {
    // 명시적 매핑
    currentUser.setName(request.getName());
    currentUser.setEmail(request.getEmail());
    // isAdmin은 절대 설정되지 않음
    
    User updated = userRepository.save(currentUser);
    return ResponseEntity.ok(updated);
}
```

### 패턴 2: @InitBinder 화이트리스트

```java
@Controller
public class UserController {
    
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // 전역 allowedFields 설정
        binder.setAllowedFields("name", "email", "phoneNumber");
    }
    
    @PostMapping("/user/update")
    public String updateUser(@ModelAttribute User user) {
        // isAdmin은 바인딩되지 않음
        userRepository.save(user);
        return "success";
    }
}
```

### 패턴 3: Immutable Entity + Builder

```java
// User.java - Immutable entity
@Entity
public class User {
    @Id
    private Long id;
    
    private final String name;
    private final String email;
    private final boolean isAdmin;
    
    // No setters - immutable
    
    @Builder
    private User(Long id, String name, String email, boolean isAdmin) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.isAdmin = isAdmin;
    }
    
    // Only expose specific update methods
    public User withName(String newName) {
        return User.builder()
            .id(this.id)
            .name(newName)
            .email(this.email)
            .isAdmin(this.isAdmin)  // 기존 값 유지
            .build();
    }
}

// Controller
@PostMapping("/user/update")
public User updateUser(@RequestBody UserUpdateRequest request, @AuthenticationPrincipal User currentUser) {
    User updated = currentUser.withName(request.getName())
                               .withEmail(request.getEmail());
    return userRepository.save(updated);
}
```

---

## 부록 D: Spring Framework 버전별 보안 변경사항

| 버전 | 보안 변경 | Breaking Change | Migration |
|------|----------|----------------|-----------|
| 5.3.18 | class.* 기본 disallowed | No | 자동 적용됨 |
| 5.3.20 | SpEL injection 패치 | No | 자동 적용됨 |
| 6.0 | JakartaEE 9+ (javax→jakarta) | Yes | Import 경로 변경 필요 |
| 6.1 | 보안 기본값 강화 | No | 권장 설정 자동 적용 |

---

## 결론

Spring MVC의 Mass Assignment 취약점은 **프레임워크의 설계 철학(편의성 우선)**과 **언어의 특성(Reflection 무제한 접근)**이 만나 발생하는 구조적 문제다.

핵심 교훈:
1. **Allow-by-default는 위험하다**: 보안은 명시적이어야 함
2. **추상화는 신뢰 경계를 숨긴다**: 개발자가 "자동 검증"을 착각
3. **편의성과 보안의 트레이드오프**: 프레임워크 선택의 근본 문제

완화는 가능하지만, **개발자의 명시적 액션**이 필요하다는 점이 여전히 위험하다.
