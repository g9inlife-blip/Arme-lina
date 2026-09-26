# NEWVERSION-003: ProtocolGame_HttpRequest 파라미터명 추출

날짜: 2026-09-26
상태: 완료 (정적 분석)

## 핵심 발견

메타데이터의 `parameterStart` 필드는 **인덱스가 아니라 바이트 오프셋**이다.
파라미터 테이블의 각 엔트리는 **12바이트** (기존에 가정한 16바이트가 아님):
- `nameIndex` (4B) → "string" 섹션의 오프셋
- `token` (4B) → 0x08xxxxxx (Param 테이블 토큰)
- `typeIndex` (4B)

## V4_POST_Login / Sign 시그니처 (확정)

```
V4_POST_Login(app_key: string, content: string, apiName: string)
Sign(content: string, apiName: string) -> string
GetDefaultParams() -> Dictionary (0 params)
```

## 전체 43개 메서드 파라미터 목록

| # | 메서드 | 파라미터 |
|---|--------|----------|
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
| 3892 | .ctor | (없음) |

## 해석

### 로그인 흐름
1. `GetDefaultParams()` → 기본 파라미터 딕셔너리 생성 (플랫폼, 버전 등)
2. 로그인용 `content` JSON 구성 (계정 정보)
3. `Sign(content, apiName)` → 서명 생성
4. `V4_POST_Login(app_key, content, apiName)` → 서명된 요청 전송

### Sign의 역할
- 입력: `content` (요청 본문), `apiName` (API 식별자)
- 출력: 서명 문자열
- `content`와 `apiName`을 조합하여 서명 → 요청 변조 방지

### 파라미터 패턴
- `app_key`: 앱 식별 키 (대부분의 POST에 포함)
- `content`: 요청 본문 (JSON 문자열로 추정)
- `apiName`: API 이름 (서명 계산에 사용)
- `merchant_id`, `app_id`, `server_id`: 결제/상점 관련 식별자

## 다음 단계
- `content`의 실제 JSON 구조는 Frida로 캡처 필요
- `Sign`의 알고리즘은 Frida로 입출력 캡처 후 역산
- `GetDefaultParams`의 반환 키는 문자열 리터럴 암호화로 인해 정적 분석 불가 → Frida 필요
