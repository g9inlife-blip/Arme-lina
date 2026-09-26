# 확정 분석 결과 (Confirmed Analysis)

> 작성일: 2026-09-26
> 목적: GPT 분석용. 정적 분석으로 확정된 사실과 미확정 항목을 명확히 구분.
> 분석 대상: `com.Alioth.JusticeSchool.kr` (저스티스스쿨, 현버전)

---

## 1. 확정 사실 (Confirmed)

### 1.1 게임 정체성
| 항목 | 값 | 근거 |
|------|-----|------|
| Package | `com.Alioth.JusticeSchool.kr` | APK 매니페스트 |
| 타이틀 | 저스티스스쿨 | APK |
| 엔진 | Unity / IL2CPP | `libil2cpp.so` 존재 |
| 아키텍처 | ARM64 | 바이너리 분석 |
| 메타데이터 버전 | 29 | `global-metadata.dat` 헤더 |

### 1.2 HTTP 통신 클래스
| 항목 | 값 | 근거 |
|------|-----|------|
| 클래스명 | `ProtocolGame_HttpRequest` | 메타데이터 타입 인덱스 433 |
| 메서드 수 | 43개 (`.ctor` 제외) | 메타데이터 메서드 테이블 |
| 메서드 인덱스 범위 | 3850–3891 | 메타데이터 |

### 1.3 핵심 메서드 시그니처 (파라미터명 포함)

```
V4_POST_Login(app_key: string, content: string, apiName: string)
Sign(content: string, apiName: string) -> string
GetDefaultParams() -> Dictionary
```

**파싱 방법 (확정):**
- 메타데이터의 `parameterStart` 필드는 **바이트 오프셋** (인덱스 아님)
- 파라미터 테이블 엔트리 크기: **12바이트**
  - `nameIndex` (4B) → string 섹션 오프셋
  - `token` (4B) → 0x08xxxxxx (Param 토큰)
  - `typeIndex` (4B)
- 메서드 3870 (`V4_POST_Login`): pstart=2448 (바이트) → 인덱스 204, 3개 파라미터
- 메서드 3883 (`Sign`): pstart=2460 (바이트) → 인덱스 205, 2개 파라미터

### 1.4 전체 43개 메서드 파라미터 목록

| 인덱스 | 메서드 | 파라미터 |
|--------|--------|----------|
| 3850 | GetTimeStamp | merchant_id |
| 3851 | AppleQuWanZhuanQian | merchant_id, app_id |
| 3852 | QuestionSubmit | merchant_id |
| 3853 | PostApplePayVerify | merchant_id |
| 3854 | PostGooglePlayVerify | merchant_id, app_id, server_id, app_key |
| 3855 | PostOneStoreVerify | app_id, server_id, app_key, content |
| 3856 | POST_GetMailDescAll | app_id |
| 3857 | POST_API_SECTION_RANK | app_id, server_id |
| 3858 | GetNoticeURL | app_id |
| 3859 | GetRegisterURL | app_id |
| 3860 | GetShopDetailURL | app_id |
| 3861 | GetTermURL | app_id |
| 3862 | GetPrivatePolicyURL | app_id |
| 3863 | GetRefundURL | server_id |
| 3864 | GetChangePwdURL | server_id |
| 3865 | GetResetPwdURL | server_id |
| 3866 | GetBindingURL | server_id |
| 3867 | GetUserinfoURL | (없음) |
| 3868 | POST_API_FCM | server_id, app_key |
| 3869 | POST_QuickRealNameAge | server_id, app_key, content, apiName, args, val |
| 3870 | V4_POST_Login | app_key, content, apiName |
| 3871 | V3_POST_Anon | app_key, content |
| 3872 | V3_POST_Order_Create | app_key, content |
| 3873 | V3_POST_AllInOne | app_key |
| 3874 | V3_POST_Gift | app_key |
| 3875 | POST_Binding | app_key, content, apiName |
| 3876 | get_retailID | (없음) |
| 3877 | get_platform | (없음) |
| 3878 | get_language | (없음) |
| 3879 | get_languageName | (없음) |
| 3880 | get_buildVerion | (없음) |
| 3881 | get_assetVerion | (없음) |
| 3882 | get_Token | (없음) |
| 3883 | Sign | content, apiName |
| 3884 | GetDefaultParams | (없음) |
| 3885 | WorldCup_Mine | content |
| 3886 | WorldCup_Fan | content, apiName |
| 3887 | WorldCup_Teams | content |
| 3888 | V3_POST_Order_Create_Steam | content, apiName, args, val |
| 3889 | PostSteamVerify | content, apiName, args |
| 3890 | PostSaveProp | apiName |
| 3891 | GetBindRealNameURL | (없음) |

### 1.5 Sign 관련 확정 사실

| 항목 | 내용 | 근거 |
|------|------|------|
| 입력 | `content` (string), `apiName` (string) | 파라미터명 추출 |
| 출력 | string (서명) | 반환 타입 |
| 암호화 상수 없음 | MD5/SHA1/SHA256 상수가 바이너리에 없음 | il2cpp 섹션 스캔 |
| 추정 | .NET `System.Security.Cryptography` 사용 | 상수 부재로 인한 추론 |
| 코드 위치 | 0x1e3ca94~0x1e40b38 클러스터 내 | 함수 청크 분석 |

### 1.6 문자열 리터럴 암호화 (확정)

| 항목 | 내용 |
|------|------|
| 상태 | 메타데이터의 문자열 리터럴이 암호화/난독화됨 |
| 영향 | API URL, 파라미터 키, 기본값 등을 정적으로 추출 불가 |
| 결론 | 동적 분석(Frida) 필수 |

### 1.7 로그인 흐름 (구조 확정)

```
1. GetDefaultParams() → 기본 파라미터 딕셔너리
2. 로그인 content JSON 구성
3. Sign(content, apiName) → 서명 생성
4. V4_POST_Login(app_key, content, apiName) → 전송
```

---

## 2. 미확정 항목 (Unconfirmed - Frida 필요)

| # | 항목 | 필요한 것 |
|---|------|-----------|
| 1 | Sign 알고리즘 | Frida로 입출력 캡처 후 역산 |
| 2 | content JSON 구조 | Frida로 실제 값 캡처 |
| 3 | GetDefaultParams 반환 키 | Frida로 딕셔너리 내용 캡처 |
| 4 | 실제 서버 URL | Frida 또는 패킷 캡처 |
| 5 | HTTP 요청 형식 | Content-Type, 헤더 등 |
| 6 | apiName 실제 값 | 예: "login"인지 확인 |

---

## 3. 가설 (Hypothesis - 검증 필요)

| # | 가설 | 검증 방법 |
|---|------|-----------|
| 1 | Sign이 MD5 또는 HMAC-SHA256 사용 | Frida 입출력 패턴 분석 |
| 2 | content가 JSON 문자열 | Frida 캡처로 확인 |
| 3 | 서버가 `ac.aliother.com` | 패킷 캡처로 확인 |

---

## 4. 산출물

| 파일 | 설명 |
|------|------|
| `research/reports/NEWVERSION-003-params.md` | 파라미터 추출 상세 |
| `research/reports/NEWVERSION-004-login-spec.md` | 로그인 스펙 종합 |
| `research/justice_hook.js` | Frida 후킹 스크립트 v2 |
| `research/test_client_skeleton.py` | 테스트 클라이언트 (Sign 미구현) |

---

## 5. 다음 단계

1. [ ] PC 확보 후 Frida 실행
2. [ ] `[SIGN_DATA]` 로그 캡처
3. [ ] Sign 알고리즘 역산
4. [ ] 테스트 클라이언트 완성
5. [ ] 실제 서버 검증
