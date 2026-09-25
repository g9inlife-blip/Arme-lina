# 현버전(저스티스스쿨) 메타데이터 분석 — 1차 결과

> 작성: 2026-09-25 (리나)
> 대상: `com.Alioth.JusticeSchool.kr_aligned.apk` (1.7GB) 내
> `assets/bin/Data/Managed/Metadata/global-metadata.dat` (11MB)
> 분석 방식: 문자열 리터럴 덤프 + grep (정밀 파싱 전 1차 스캔)

## 1. TASK-007 §0 판정: HTTP 로그인 트랙 — 살아있음 ✅

| 문자열 | hits | 판정 |
|---|---|---|
| `V4_POST_Login` | 5 | ✅ 존재 |
| `ac.aliother.com` | 1 | ✅ 존재 |
| `API_Login` | 3 | ✅ 존재 |
| `V3_POST_AllInOne` | 4 | ✅ 존재 |

→ TASK-007 §1(HTTP 로그인 파라미터)·§2(Sign 역분석) **진행 확정**.
레거시 트랙이 아니었다.

## 2. 신규 확인된 서버 엔드포인트

| 용도 | URL |
|---|---|
| HTTP API 베이스 | `https://ac.aliother.com/v3/ain1` |
| 통계/로그 | `https://gm.aliother.com/s1/stat/log` |
| (참고) 기타 ain1 | `https://api.cyberhoney.rekoo.net/ain1`, `https://loginba.nrnsoft.com/ain1` |

API path 상수 (`API_*`):
`API_Login`, `API_Anon`, `API_account_anon`, `API_Mail`, `API_Pay`, `API_GIFT`,
`API_SaveProps`, `API_SECTION_RANK`,
결제 검증계: `API_ApplePayVerify`, `API_GooglePlayVerify`, `API_OnestorePlayVerify`,
`API_SteamVerify`, `API_Steam_Pay`, `API_MARK_AliPay`, `API_MARK_WePay`,
`API_MARK_BliPay`, `API_MARK_QuickSDKPay`, `API_MARK_GamePotPay`,
`API_MARK_SteamPay`, `API_QUICKSDK_AUTH`, `API_FCM`

→ 베이스 URL + `API_*` 상수 조합이 실제 요청 path일 가능성 높음.
`contracts/AUTH.md` A1에 반영.

## 3. 후킹 포인트 생존 확인 (HOOKING_PLAN §3)

| 포인트 | hits | 상태 |
|---|---|---|
| `DecryptUnSafe` | 4 | ✅ |
| `ProccessRequestRes` | 4 | ✅ |
| `SendRequest` | 14 | ✅ |
| `OpInfo` | 2 | ✅ |
| `ProtocolGame` | 5 | ✅ |
| `Sign` / `SignDic` / `SignData` | 다수 | ✅ |

→ HOOKING_PLAN의 P0/P1 포인트가 현버전에도 그대로 존재.
단, RVA는 구버전 기준이므로 **메서드명 기준 재탐색 필요**.

## 4. 로그인 관련 신규 단서

- `CS_Last_Server_IP`, `CS_Last_Server_Port` — 클라이언트가 마지막 접속 서버 IP/Port를 저장.
  로컬 서버 연동 시 이 값을 활용하면 DNS/hosts 조작 없이도 가능할 수 있음.
- `CS_Last_Login_Uid`, `CS_Last_Login_Pwd`, `CS_Last_Guest_ID` — 저장된 로그인 정보 키.
- `ClickGuestLogin`, `ClickAccountLogin`, `AutoLogin` — 게스트/계정 로그인 경로 둘 다 존재.
- `CmdDupLogin` — 중복 로그인 관련 명령어.

## 5. 안티치트: ACTk (Anti-Cheat Toolkit)

- CodeStage ACTk 사용 확인 (`InjectionDetector`, `ObscuredCheatingDetector`,
  `SpeedHackDetector`, `TimeCheatingDetector`, `WallHackDetector`).
- 네이티브 `TracerPid:` 검사도 존재 (디버거 탐지).
- Frida/Xposed/Magisk 전용 탐지 문자열은 없음 (오탐 제외).
- → HOOKING_PLAN §5에 반영. Frida는 네이티브 레벨이라 ACTk managed 탐지를
  직접 건드리지 않지만, 실행 시 행위 탐지에 걸릴 수 있음.

## 6. 구버전 흔적

- `com.thumbage.heroes.google`, `com.thumbage.heroes.ios`, `com.thumbage.heroes.onestore`
  문자열이 메타데이터에 잔존 (계정 마이그레이션/채널 참조용으로 추정).
- 신규: `com.Alioth.JusticeSchool`, `com.Alioth.JusticeSchool.cn`.

## 7. 다음 단계

1. `V4_POST_Login` 5개 hits의 문맥 파악 (메서드명인지 문자열 리터럴인지)
   → Il2CppDumper 등으로 메서드 → RVA 매핑 후 정적 분석
2. `Sign(signKey, dict)` 메서드 특정 + 서명 알고리즘 확인
3. `API_Login` path 조합 규칙 확인 (베이스 URL + 상수)
4. 필요 시 정밀 메타데이터 파싱 (string literal 오프셋 → 사용처 추적)

## 8. 원본 파일 (Git 제외)

- `~/workspace/apk/com.Alioth.JusticeSchool.kr_aligned.apk` (1.7GB)
- `~/workspace/apk/libil2cpp.so` (53MB, 별도 수신)
- `~/workspace/apk/metadata.strings.txt` (덤프 결과)
- `~/workspace/apk/libil2cpp.strings.txt` (네이티브 문자열 덤프)
