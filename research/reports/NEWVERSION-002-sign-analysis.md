# Sign / V4_POST_Login 정적 분석 — 2차 결과 및 Frida 계획

> 작성: 2026-09-25 (리나)
> 상태: 정적 분석은 한계 도달 → Frida 동적 분석으로 전환 (사용자가 PC 확보 후 진행)

## 1. 메서드 식별 완료

`ProtocolGame_HttpRequest` (Assembly-CSharp, type 433) — 43개 메서드 전체가 static (.ctor 제외)

| 인덱스 | 메서드 | 파라미터 | token_rid | 비고 |
|---|---|---|---|---|
| 3870 | `V4_POST_Login` | 3 | 3871 | 로그인 요청 본체 |
| 3883 | `Sign` | 2 | 3884 | 서명 생성 (핵심 타겟) |
| 3884 | `GetDefaultParams` | 0 | 3885 | 기본 파라미터 딕셔너리 생성 |

전체 목록: GetTimeStamp, AppleQuWanZhuanQian, QuestionSubmit, PostApplePayVerify,
PostGooglePlayVerify, PostOneStoreVerify, POST_GetMailDescAll, POST_API_SECTION_RANK,
GetNoticeURL, GetRegisterURL, GetShopDetailURL, GetTermURL, GetPrivatePolicyURL,
GetRefundURL, GetChangePwdURL, GetResetPwdURL, GetBindingURL, GetUserinfoURL,
POST_API_FCM, POST_QuickRealNameAge, V4_POST_Login, V3_POST_Anon,
V3_POST_Order_Create, V3_POST_AllInOne, V3_POST_Gift, POST_Binding,
get_retailID, get_platform, get_language, get_languageName, get_buildVerion,
get_assetVerion, get_Token, Sign, GetDefaultParams, WorldCup_Mine, WorldCup_Fan,
WorldCup_Teams, V3_POST_Order_Create_Steam, PostSteamVerify, PostSaveProp,
GetBindRealNameURL, .ctor

## 2. 코드 위치 특정

- IL2CPP 생성 코드는 `.text`가 아닌 커스텀 **`il2cpp` 섹션** (0xaa326c, ~28MB)에 존재
- `ProtocolGame_HttpRequest` 메서드들이 **0x1e3ca94 ~ 0x1e40b38** (16KB)에 클러스터링
- 36개 함수 청크 식별 (ret 기준 분할)
- 대형 함수 (>1KB, POST 메서드 후보): 0x1e3d0f0, 0x1e3df40, 0x1e3e7a8, 0x1e3f1a8, 0x1e3fa44

### Il2CppDumper 매핑 규칙 (v24.2+, 2021.3 포함)
```
주소 = CodeGenModule[imageName].methodPointers[(methodToken & 0x00FFFFFF) - 1]
```
- V4_POST_Login: ptrs[3870]
- Sign: ptrs[3883]
- 단, 어셈블리별 CodeGenModule 구조체를 바이너리에서 특정하지 못함 (모듈명 문자열이 .so에 없음)

## 3. 정적 분석의 한계

1. **암호화 상수 없음**: MD5/SHA1/SHA256 상수가 il2cpp 섹션에 없음
   → Sign이 게임 코드에 직접 구현된 게 아니라 .NET `System.Security.Cryptography` 호출 추정
2. **문자열 리터럴 접근 패턴 미파악**: `ac.aliother.com` 등 URL 문자열이 .so에 없음 (메타데이터에만 존재)
   → IL2CPP 2021.3 ARM64의 string literal 로드 패턴을 역추적하지 못함
3. **Sign 후보 함수 특정 불가**: 중형 함수들에 crypto 연산(eor/lsl/lsr) 패턴 없음
   → .NET 라이브러리 호출 via virtual dispatch로 추정

## 4. Frida 동적 분석 계획 (다음 단계)

스크립트: `~/workspace/apk/justice_hook.js`

### 후킹 포인트
- `ProtocolGame_HttpRequest.V4_POST_Login` (3 params) — 입력 파라미터 캡처
- `ProtocolGame_HttpRequest.Sign` (2 params) — 입력 → 출력 쌍 캡처
- `ProtocolGame_HttpRequest.V3_POST_AllInOne` (1 param) — 전체 흐름 확인

### 실행 방법 (PC 필요)
```bash
pip install frida-tools
# 폰에 frida-server 실행 (루팅 필요)
frida -U -f com.Alioth.JusticeSchool.kr -l justice_hook.js --no-pause
# 게임에서 로그인 → 터미널에 파라미터/서명 출력
```

### 기대 결과
- Sign의 입력 문자열 형식 확인 (예: 정렬된 파라미터 조합)
- 입력 → 출력 쌍을 여러 개 수집하여 알고리즘 역산
  (예: "param1=v1&param2=v2" → MD5 → 대문자 hex 같은 패턴)

## 5. 다음 작업

1. [ ] 사용자 PC 확보 후 Frida 실행
2. [ ] Sign 입출력 로그 수집
3. [ ] 알고리즘 역산 → 스펙 문서 작성
4. [ ] 테스트 클라이언트 구현 (사용자 담당)
