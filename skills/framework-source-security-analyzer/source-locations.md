# 프레임워크별 핵심 소스 파일 위치 가이드

보안 분석 시 우선적으로 조사할 소스 파일 경로와 GitHub 위치를 정리한 문서.

---

## Spring Framework

### GitHub Repository
`https://github.com/spring-projects/spring-framework`

### 핵심 보안 관련 파일

#### 1. Data Binding (Mass Assignment)
```
spring-web/src/main/java/org/springframework/web/bind/
├── WebDataBinder.java          # Request parameter 바인딩
├── ServletRequestDataBinder.java
└── annotation/
    └── ModelAttribute.java     # @ModelAttribute 처리
```

#### 2. Spring MVC Security
```
spring-webmvc/src/main/java/org/springframework/web/servlet/
├── DispatcherServlet.java      # 요청 처리 진입점
├── mvc/method/annotation/
│   ├── RequestMappingHandlerAdapter.java
│   └── ModelAttributeMethodProcessor.java
└── view/
    └── AbstractView.java       # View rendering
```

#### 3. Spring Expression Language (SpEL)
```
spring-expression/src/main/java/org/springframework/expression/
├── spel/
│   ├── standard/SpelExpressionParser.java  # SpEL 파서
│   └── support/StandardEvaluationContext.java
└── Expression.java
```

#### 4. Spring Security
```
https://github.com/spring-projects/spring-security
spring-security-core/src/main/java/org/springframework/security/
├── core/
│   ├── context/SecurityContext.java
│   └── Authentication.java
├── authentication/
│   └── AuthenticationManager.java
└── access/
    └── expression/SecurityExpressionRoot.java  # SpEL in @PreAuthorize
```

#### 5. Spring Boot Actuator
```
https://github.com/spring-projects/spring-boot
spring-boot-project/spring-boot-actuator/src/main/java/
└── org/springframework/boot/actuate/
    ├── endpoint/
    │   └── web/WebEndpointProperties.java  # Endpoint 설정
    └── autoconfigure/
        └── security/servlet/ManagementWebSecurityAutoConfiguration.java
```

---

## Django

### GitHub Repository
`https://github.com/django/django`

### 핵심 보안 관련 파일

#### 1. Model Forms (Mass Assignment)
```
django/forms/
├── models.py                   # ModelForm 정의
├── fields.py                   # Field validation
└── widgets.py
```

#### 2. ORM and Database
```
django/db/
├── models/
│   ├── query.py               # QuerySet (SQL Injection 가능)
│   └── sql/
│       └── compiler.py        # SQL 생성
└── backends/
    └── utils.py               # SQL escaping
```

#### 3. Template Engine
```
django/template/
├── base.py                    # Template 클래스 (Injection 위험)
├── loader.py
├── backends/
│   └── django.py             # DTL backend
└── defaulttags.py            # 내장 태그
```

#### 4. Middleware and Security
```
django/middleware/
├── csrf.py                    # CSRF 보호
├── security.py                # Security headers
└── clickjacking.py            # X-Frame-Options

django/core/
└── signing.py                 # 서명 검증
```

#### 5. Authentication
```
django/contrib/auth/
├── models.py                  # User model
├── backends.py                # Auth backends
└── hashers.py                 # Password hashing
```

---

## Express.js

### GitHub Repository
`https://github.com/expressjs/express`

### 핵심 보안 관련 파일

#### 1. Core Router
```
lib/
├── application.js             # Express app
├── router/
│   ├── index.js              # Router
│   └── route.js              # Route handling
└── middleware/
    ├── init.js
    └── query.js              # Query string parsing
```

#### 2. Body Parser (별도 모듈)
```
https://github.com/expressjs/body-parser
lib/types/
├── json.js                   # JSON parsing (Prototype pollution)
├── urlencoded.js
└── raw.js
```

#### 3. Static File Serving
```
https://github.com/expressjs/serve-static
index.js                      # Path traversal 가능성
```

---

## Java Standard Library

### OpenJDK Repository
`https://github.com/openjdk/jdk`

### 핵심 보안 관련 파일

#### 1. URL Parsing
```
src/java.base/share/classes/java/net/
├── URL.java                   # getHost() vs getAuthority()
├── URI.java                   # 더 안전한 대안
└── URLStreamHandler.java
```

#### 2. Serialization
```
src/java.base/share/classes/java/io/
├── ObjectInputStream.java     # Deserialization (RCE)
├── ObjectOutputStream.java
└── Serializable.java
```

#### 3. XML Parsing
```
src/java.xml/share/classes/javax/xml/parsers/
├── DocumentBuilderFactory.java  # XXE 취약
├── SAXParserFactory.java
└── DocumentBuilder.java

src/java.xml/share/classes/com/sun/org/apache/xerces/internal/
└── parsers/                   # 실제 파서 구현
```

#### 4. Reflection
```
src/java.base/share/classes/java/lang/reflect/
├── Method.java                # Method.invoke() 보안
├── Constructor.java
└── Field.java
```

---

## Python Standard Library

### CPython Repository
`https://github.com/python/cpython`

### 핵심 보안 관련 파일

#### 1. Pickle
```
Lib/pickle.py                  # Deserialization (RCE)
Modules/_pickle.c              # C implementation
```

#### 2. Subprocess
```
Lib/subprocess.py              # Command injection 가능
```

#### 3. XML Parsing
```
Lib/xml/
├── etree/
│   └── ElementTree.py        # XXE 취약
└── sax/
    └── saxutils.py
```

#### 4. eval/compile
```
Python/bltinmodule.c           # eval, exec 구현
Lib/ast.py                     # AST parsing
```

---

## ASP.NET Core

### GitHub Repository
`https://github.com/dotnet/aspnetcore`

### 핵심 보안 관련 파일

#### 1. Model Binding
```
src/Mvc/Mvc.Core/src/ModelBinding/
├── ModelBindingContext.cs     # Binding context
├── Binders/
│   ├── ComplexObjectModelBinder.cs  # Mass assignment
│   └── SimpleTypeModelBinder.cs
└── ParameterBinder.cs
```

#### 2. Middleware
```
src/Middleware/
├── CORS/src/
│   └── CorsMiddleware.cs     # CORS 처리
├── Session/src/
│   └── SessionMiddleware.cs
└── StaticFiles/src/
    └── StaticFileMiddleware.cs  # Path traversal 가능
```

#### 3. Authentication
```
src/Security/Authentication/Core/src/
├── AuthenticationService.cs
└── AuthenticationHandler.cs
```

---

## Ruby on Rails

### GitHub Repository
`https://github.com/rails/rails`

### 핵심 보안 관련 파일

#### 1. Active Record
```
activerecord/lib/active_record/
├── base.rb                    # Model 정의
├── relation.rb                # Query building
├── connection_adapters/
│   └── abstract/
│       └── quoting.rb        # SQL escaping
└── attribute_assignment.rb    # Mass assignment
```

#### 2. Action Controller
```
actionpack/lib/action_controller/
├── metal/
│   ├── strong_parameters.rb  # Parameter filtering
│   └── params_wrapper.rb
└── base.rb
```

#### 3. Action View
```
actionview/lib/action_view/
├── template.rb                # Template rendering
├── helpers/
│   └── sanitize_helper.rb    # XSS 방지
└── template/
    └── resolver.rb
```

---

## Node.js Core

### GitHub Repository
`https://github.com/nodejs/node`

### 핵심 보안 관련 파일

#### 1. URL Parsing
```
lib/
├── url.js                     # URL parsing
└── internal/
    └── url.js                # WHATWG URL implementation
```

#### 2. Child Process
```
lib/
├── child_process.js           # Command injection 위험
└── internal/
    └── child_process.js
```

#### 3. VM Module
```
lib/
└── vm.js                      # Code execution sandbox
```

---

## 분석 우선순위

각 프레임워크 분석 시 다음 순서로 소스를 조사:

### 1단계: 핵심 진입점
- Request handling entry point
- Router/dispatcher
- Middleware chain

### 2단계: 데이터 처리
- Parameter binding
- Deserialization
- Template rendering

### 3단계: 보안 메커니즘
- Authentication/Authorization
- CSRF protection
- Input validation

### 4단계: 설정 및 기본값
- Configuration files
- Auto-configuration
- Default settings

---

## 버전별 차이 주의사항

### Spring
- Spring Boot 2.x vs 3.x: Actuator 기본 노출 범위 다름
- Spring Framework 5.x vs 6.x: Security 설정 변경

### Django
- Django 3.x vs 4.x: CSRF 토큰 처리 변경
- Django 2.x vs 3.x: URL routing 변경

### Express
- Express 4.x vs 5.x (beta): 미들웨어 처리 변경

### Java
- Java 8 vs 11 vs 17 vs 21: Serialization filter 도입 시기
- Java 9+: Module system 영향

---

## 문서 참고 위치

각 프레임워크의 공식 보안 문서:

- Spring: `https://docs.spring.io/spring-security/reference/`
- Django: `https://docs.djangoproject.com/en/stable/topics/security/`
- Express: `https://expressjs.com/en/advanced/best-practice-security.html`
- ASP.NET: `https://learn.microsoft.com/en-us/aspnet/core/security/`
- Rails: `https://guides.rubyonrails.org/security.html`

---

이 가이드를 사용하여:
1. web_search로 관련 파일 찾기
2. web_fetch로 실제 소스코드 조회
3. 버전별 차이 확인
4. 공식 문서와 교차 검증
