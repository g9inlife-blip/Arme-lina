# NEWVERSION-004: JusticeSchool 로그인 플로우 스펙

날짜: 2026-09-26
상태: 정적 분석 완료, 동적 분석(Frida) 대기 중

## 개요

JusticeSchool (`com.Alioth.JusticeSchool.kr`)의 로그인 HTTP 통신 스펙.
`ProtocolGame_HttpRequest` 클래스의 43개 메서드를 분석하여 추출.

## API 시그니처 (확정)

### 로그인
```
V4_POST_Login(app_key: string, content: string, apiName: string)
```

### 서명
```
Sign(content: string, apiName: string) -> string
```

### 기본 파라미터
```
GetDefaultParams() -> Dictionary
```

## 로그인 흐름

```
1. GetDefaultParams() 호출
   → 기본 파라미터 딕셔너리 획득 (플랫폼, 버전 등)
   
2. 로그인 content 구성
   → JSON 문자열 (계정 ID, 비밀번호 등 포함)
   → ⚠️ 실제 구조는 Frida 캡처 필요
   
3. Sign(content, apiName) 호출
   → 서명 문자열 생성
   → ⚠️ 알고리즘은 Frida 캡처 필요
   
4. V4_POST_Login(app_key, content, apiName) 호출
   → 서명된 요청을 서버로 전송
   → ⚠️ 실제 URL과 요청 형식은 캡처 필요
```

## 파라미터 설명

| 파라미터 | 설명 | 비고 |
|----------|------|------|
| app_key | 앱 식별 키 | APK에서 추출 가능 |
| content | 요청 본문 (JSON) | 로그인 정보 포함 |
| apiName | API 식별자 | "login" 등으로 추정 |
| sign | Sign()의 출력 | 요청 변조 방지 |

## 정적 분석으로 확정된 사실

1. **메서드 시그니처**: 43개 메서드 전체의 파라미터명 추출 완료
   - 참고: `NEWVERSION-003-params.md`

2. **Sign의 입출력**: `content`와 `apiName`을 입력받아 서명 문자열 반환
   - 암호화 상수(MD5/SHA)가 바이너리에 없음
   - .NET `System.Security.Cryptography` 사용 추정

3. **문자열 리터럴 암호화**: 메타데이터의 문자열이 암호화되어 있음
   - API URL, 파라미터 키 등을 정적으로 추출 불가
   - Frida 동적 분석 필수

## Frida로 캡처해야 할 것

### 1. Sign 입출력
```
[Sign] content="...", apiName="..." -> "..."
```
- 다양한 입력에 대한 출력을 수집
- 알고리즘 역산 (MD5? HMAC? 커스텀?)

### 2. content 구조
```
[V4_POST_Login] app_key="...", content="...", apiName="..."
```
- content JSON의 실제 키 목록
- 필수 필드 vs 선택 필드

### 3. GetDefaultParams 반환값
```
[GetDefaultParams] -> {...}
```
- 기본 파라미터의 키 목록

### 4. 실제 HTTP 요청
- URL (호스트, 경로)
- HTTP 메서드 (POST 확정)
- Content-Type (JSON? form?)
- 헤더

## 테스트 클라이언트

스켈레톤 작성 완료: `~/workspace/apk/test_client_skeleton.py`

사용 순서:
1. Frida 캡처 실행
2. 캡처 로그 분석 → Sign 알고리즘 확정
3. `sign()` 함수 구현
4. `build_login_content()` 함수 구현 (실제 content 구조)
5. `get_default_params()` 함수 구현
6. `BASE_URL`, `API_LOGIN` 상수 확정
7. 테스트 실행

## 참고 자료

- `NEWVERSION-002-sign-analysis.md`: Sign 정적 분석 상세
- `NEWVERSION-003-params.md`: 전체 파라미터 목록
- `justice_hook.js`: Frida 후킹 스크립트
- `test_client_skeleton.py`: 테스트 클라이언트 스켈레톤

## 다음 단계

- [ ] 사용자 PC 확보
- [ ] Frida 실행 및 로그 캡처
- [ ] Sign 알고리즘 역산
- [ ] 테스트 클라이언트 완성
- [ ] 실제 서버 대상 검증
