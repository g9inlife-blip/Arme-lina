# TASK-007 — Login Request/Response 디컴파일 증거 확보

## 목적

TASK-006에서 정적 이름 수준까지는 확인됐으나, 다음 항목들이 디컴파일/어셈블리 증거 없이 PROBABLE/UNKNOWN으로 남아 있다.

```text
1. ProtocolGame_HttpRequest.V4_POST_Login     RVA 0xCD5B48
2. ProtocolGame_HttpRequest.Sign              RVA 0xCD95C0
3. ProtocolGame_SendRequest.Login             RVA 0xCDE818
4. TCPTube handshake / send / receive
5. DataCenter.ProccessRequestRes
```

이 TASK는 위 5개 함수의 **실제 동작을 증거로 확정**하는 것이 목표다. 추측으로 계약을 만들지 않는다.

## 조사 대상 (우선순위 순)

### 1. `V4_POST_Login(uid, pwd, type)` — RVA 0xCD5B48
- 파라미터 딕셔너리에 실제로 들어가는 키 목록을 전부 기록한다.
  (`uid`, `pwd`, `type` 외에 `GetDefaultParams()`가 추가하는 키 포함)
- 최종 URL path를 확정한다. (`API_Login` 문자열이 path의 어디에 들어가는지)
- HTTP method (POST 확정 여부), Content-Type, body 인코딩(JSON/form/기타)을 기록한다.
- `Sign()` 호출 위치와 서명된 파라미터 범위를 기록한다.

### 2. `Sign(signKey, dict)` — RVA 0xCD95C0
- 서명 알고리즘을 확정한다. (HMAC-SHA256 / MD5 / 커스텀 등)
- `signKey`의 출처를 추적한다. (상수 / 서버에서 받은 값 / 디바이스 파생값)
- 서명 대상 문자열의 조합 규칙을 기록한다. (키 정렬, 구분자, 인코딩)
- 서명값이 들어가는 파라미터 키 이름을 기록한다.

### 3. `ProtocolGame_SendRequest.Login()` — RVA 0xCDE818
- 생성되는 `OpInfo`의 필드 할당을 전부 기록한다.
  (`OpCode = 2` 외에 `User`, `SerialNumber`, `Time` 등에 뭐가 들어가는지)
- token이 `OpInfo`의 어디에 들어가는지 기록한다.
- `CSBehaviour.RequestOp` 호출 전후 흐름을 기록한다.

### 4. TCPTube handshake
- `CSBehaviour.Connect(ip, port, token)` 이후 첫 패킷 구조를 기록한다.
- `CmdHandshake1 = 1` / `CmdHandshake2 = 2` 패킷의 필드 구성을 기록한다.
- `CmdEncrypt = 128` / `CmdCompress = 64` 플래그가 실제로 언제 켜지는지 기록한다.
- `Crypto.EncryptUnSafe / DecryptUnSafe`와의 연결을 확인한다.

### 5. `DataCenter.ProccessRequestRes`
- Login 응답 `OpInfo`에서 읽는 필드를 전부 기록한다.
- 어떤 Player State 딕셔너리가 초기화되는지 기록한다.
  (`User`, `Heros`, `Items`, `Weapons`, `Equiments`, `Mails`, `Chapters`, `Sections`, `Teams`, `Shops`, `Activities`)
- Main Menu 진입을 위해 **필수**인 필드와 없어도 되는 필드를 구분한다.

## 반드시 기록할 증거

각 함수마다:
- RVA / 함수명
- decompile 핵심 구간 (필드 할당 부분 위주)
- assembly 핵심 5~20줄 (인라인/최적화로 decompile이 깨지는 구간)
- XREF (caller → callee)
- 관련 문자열 리터럴
- **판단 근거를 문장으로** (이름만 보고 단정 금지)

## 결과 파일

`research/reports/TASK-007-result.md` — `research/templates/TASK-RESULT.md` 형식 사용.

## 종료 기준

다음 중 하나라도 증거와 함께 확정되면 성공이다:
- `V4_POST_Login`의 전체 파라미터 + 서명 규칙
- `SendRequest.Login`의 전체 `OpInfo` 필드
- TCPTube handshake 패킷 구조

전부 실패해도 조사한 경로와 막힌 지점을 기록하면 TASK는 종료한다.

## 수정 금지

이 TASK에서는 APK/so/metadata를 수정하지 않는다. Local Server 구현도 하지 않는다.
