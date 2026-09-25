# AUTH Contract

> 출처: `research/reports/TASK-006-result.md`, `research/CRYPTO_TRANSPORT.md`
> 상태: 작성 중 (2026-09-25)

## A1. HTTP 로그인 토큰

```text
Action: 로그인 토큰 발급
Endpoint/Command: API_Login (HTTP)
Transport: HTTPS — CONFIRMED (현버전 메타데이터)
Base URL: https://ac.aliother.com/v3/ain1 (CONFIRMED, 2026-09-25)
Request Type: HttpRequest (V4_POST_Login — 현버전 존재 확인됨)
Request Fields:
  uid: PROBABLE
  pwd: PROBABLE
  type: PROBABLE
  default params (d, v, r/token 등): PROBABLE
  서명 필드: UNKNOWN (Sign 알고리즘 미확정)
Serializer: UNKNOWN
Encryptor: TLS (application crypto 해당 없음 — PROBABLE)
Response Type: Response_GetLoginToken
Response Fields:
  Status: CONFIRMED (이름)
  UserId: CONFIRMED (이름)
  Token: CONFIRMED (이름)
  Desc: CONFIRMED (이름)
  First: CONFIRMED (이름)
  method: CONFIRMED (이름)
  BindFacebook / BindGoogle / BindGameCenter: CONFIRMED (이름)
  RealName: CONFIRMED (이름)
  FCMStatus: CONFIRMED (이름)
  logout_ex_time: CONFIRMED (이름)
Deserializer: UNKNOWN (JSON 추정 — 미확정)
Client Handler: LoginManager.OnLoginSucceedAction → LoginManager.LoginGameServer
State Effect: LoginManager.SaveLoginToken, GamePlayerInfomation.LoginToken — PROBABLE
Persistence Effect: UNKNOWN
Success Code: Status 값 의미 미확정 — UNKNOWN
Evidence: dump.cs 정적 증거
Confidence: PROBABLE (필드 이름) / UNKNOWN (값 의미·직렬화)
Runtime Verified: no
Next API Dependency: API_Allin1 → 게임 서버 Connect
```

## A2. 게스트 계정

```text
Action: 익명/게스트 계정 발급
Endpoint/Command: API_Anon (V3_POST_Anon)
Response Type: Response_Account_Anon
Response Fields:
  RoleId / UserId / Token / Desc / Retail / First / logout_ex_time: CONFIRMED (이름)
Confidence: PROBABLE (필드 이름)
Runtime Verified: no
```

## A3. 부트스트랩 (All-in-one)

```text
Action: 서버 목록/에셋/CDN 정보 조회
Endpoint/Command: API_Allin1 (V3_POST_AllInOne)
Response Type: Response_Allin1
Response Fields:
  Status / NoticeStatus / NoticeTime / IP / IsUpgrade: CONFIRMED (이름)
  Assets / Keys / Servers / Http_API_URL / AssetVersion / BestCDN: CONFIRMED (이름)
  Server.Host / Server.Port: CONFIRMED (이름)
Default Server: gm.aliother.com:8000 (정적 상수) / PCAP 관측 182.92.62.79:8000
Confidence: PROBABLE (필드 이름)
Runtime Verified: no
Next API Dependency: 게임 서버 TCP Connect (:8000)
```

## A4. 게임 서버 로그인

```text
Action: 게임 서버 로그인
Endpoint/Command: OperationCode.Login = 2 (TCP :8000)
Transport: TCP, DH64 세션키 + Rijndael CBC/PKCS7 — CONFIRMED (CRYPTO_TRANSPORT.md)
Request Type: Request(OpInfo) — ProtocolGame_SendRequest.Login()
Request Fields: UNKNOWN (OpInfo 필드 할당 미확정)
Response Type: OpInfo
Response Fields: UNKNOWN (DataCenter.ProccessRequestRes 분석 필요)
Client Handler: CSBehaviour.Response → DataCenter.ProccessRequestRes
State Effect: DataCenter.User 및 초기 딕셔너리 초기화 — PROBABLE
Confidence: PROBABLE (전송 계층) / UNKNOWN (OpInfo 필드)
Runtime Verified: no
Next API Dependency: Main bootstrap state 요청들 (순서 미확정)
```

## 다음 조사

TASK-007 §1–§4 참조.
