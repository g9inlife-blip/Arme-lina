# TASK-007 — Login HTTP + OpInfo + 압축/프로토콜 잔여 증거 확보

> 개정: 2026-09-25 (리나)
>
> 개정 사유: 초판에서 요구한 TCPTube handshake / DH64 / Rijndael 분석은
> 2026-09-21/22 분석에서 이미 확정됐다 (`research/CRYPTO_TRANSPORT.md` 참조).
> 이 TASK는 **아직 확정되지 않은 잔여 항목**에만 집중한다.

## 확정된 것 (이 TASK에서 다시 조사하지 않음)

- DH64: `g = 5`, `p = 2^64 - 59`, 이중 DH → 16-byte session key
- TCP/KCP handshake wire layout (PCAP 대조 완료)
- Rijndael: CBC / PKCS7 / 128-bit block, `IV = payload[0:16]`
- `Tools.DecryptUnSafe()` 복호화 흐름
- 암호화 payload = `[16-byte IV][ciphertext]`
- 복호화 후 protobuf OpInfo deserialize

## 조사 대상 (우선순위 순)

### 0. 전제 검증 — HTTP 로그인 트랙이 현재 클라이언트에 살아있는가 ✅ **확정 (2026-09-25)**
- 현버전 `global-metadata.dat`에서 `V4_POST_Login`(5), `ac.aliother.com`(1),
  `API_Login`(3), `V3_POST_AllInOne`(4) 확인 → **트랙 살아있음**
- 신규 엔드포인트: `https://ac.aliother.com/v3/ain1`, `https://gm.aliother.com/s1/stat/log`
- 상세: `research/reports/NEWVERSION-001-metadata.md`
- 이에 따라 §1·§2 진행 확정. 아래는 §0의 원래 게이트 기록 (보존):
- `V4_POST_Login` / `ac.aliother.com` / `API_Login` 문자열 참조가 **현재 버전 클라이언트**에 여전히 존재하는지 확인
- 존재하지 않거나 dead code면 §1·§2(HTTP 로그인 + Sign)는 **스킵**하고 §3·§4(게임 서버 로그인)에 집중
- 배경: 2026-09-21 PCAP에는 `:8000` 게임 서버 트래픽만 관측됐고, HTTP 로그인 트랙의 현재 유효성은 미검증 상태다.
  레거시 트랙을 역분석하는 헛수고를 피하기 위한 게이트다.
- "게임이 TLS pinning을 port 80/HTTP로 우회 송출한다"는 주장의 근거도 함께 확인
  (실제 캡처 확인인지 추정인지, 어느 endpoint가 :80인지)
> **버전 전환 주의 (2026-09-25):** 기존 RVA·증거는 구버전(아르메블랑쉐 / `com.thumbage.heroes.google`) 기준이다.
> 현버전(저스티스스쿨 / `com.Alioth.JusticeSchool.kr`) APK에서 §0~§7 전 항목을 재검증해야 한다.
> RVA가 바뀌었을 수 있으므로 함수명 기준으로 먼저 탐색한다.

### 1. HTTP 로그인 요청 — `V4_POST_Login` (RVA 0xCD5B48)
> §0에서 트랙 유효성이 확인된 경우에만 수행
- 파라미터 딕셔너리의 전체 키 목록 (`uid`, `pwd`, `type` + `GetDefaultParams()` 추가분)
- 최종 URL path (`API_Login`이 path의 어디에 들어가는지)
- HTTP method, Content-Type, body 인코딩 (JSON / form / 기타)
- `Sign()` 호출 위치와 서명 대상 파라미터 범위

### 2. 서명 — `Sign(signKey, dict)` (RVA 0xCD95C0)
- 서명 알고리즘 확정 (HMAC-SHA256 / MD5 / 커스텀 등)
- `signKey` 출처 추적 (상수 / 서버 수신값 / 디바이스 파생값)
- 서명 대상 문자열 조합 규칙 (키 정렬, 구분자, 인코딩)
- 서명값이 들어가는 파라미터 키 이름

### 3. 게임 서버 로그인 — `ProtocolGame_SendRequest.Login()` (RVA 0xCDE818)
- 생성되는 `OpInfo`의 필드 할당 전부 (`OpCode = 2` 외 `User`, `SerialNumber`, `Time` 등)
- token이 `OpInfo`의 어디에 들어가는지
- `CSBehaviour.RequestOp` 호출 전후 흐름

### 4. `DataCenter.ProccessRequestRes`
- Login 응답 `OpInfo`에서 읽는 필드 전부
- 초기화되는 Player State 딕셔너리 (`User`, `Heros`, `Items`, `Weapons`, `Equiments`, `Mails`, `Chapters`, `Sections`, `Teams`, `Shops`, `Activities`)
- Main Menu 진입에 **필수**인 필드 vs 없어도 되는 필드 구분

### 5. 압축 — 0x40 flag
- 압축 알고리즘 확정 (decompress 함수 XREF 추적)
- 압축 적용 조건 (어떤 OpCode/크기에서 켜지는지)

### 6. protobuf OpInfo 매핑
- `OpInfo` protobuf field 목록 (최소 Login 관련)
- `OperationCode` 전체 목록 (현재 `Login = 2`만 확인)
- Request ↔ Response correlation 방식

### 7. Client handshake param4 (344 bytes)
- TCP handshake `0x1D` 이후 344 bytes의 의미
- 로그인/인증 관련 parameter인지 확인
- RSA로 단정하지 말고 실제 생성 코드 추적

## 반드시 기록할 증거

각 항목마다:
- RVA / 함수명
- decompile 핵심 구간 (필드 할당 위주)
- assembly 핵심 5~20줄 (decompile이 깨지는 구간)
- XREF (caller → callee)
- 관련 문자열 리터럴
- 판단 근거 문장 (이름만 보고 단정 금지)

## 결과 파일

`research/reports/TASK-007-result.md` — `research/templates/TASK-RESULT.md` 형식 사용.

## 종료 기준

다음 중 하나라도 증거와 함께 확정되면 성공:
- `V4_POST_Login` 전체 파라미터 + 서명 규칙
- `SendRequest.Login` 전체 `OpInfo` 필드
- 0x40 압축 알고리즘
- OpInfo protobuf 필드 매핑 (Login 범위)

전부 실패해도 조사 경로와 막힌 지점을 기록하면 TASK 종료.

## 수정 금지

이 TASK에서는 APK/so/metadata를 수정하지 않는다. Local Server 구현도 하지 않는다.
