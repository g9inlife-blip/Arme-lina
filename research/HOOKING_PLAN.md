# Hooking 분석 개념 — 대규모 모바일 게임(IL2CPP) 적용 계획

> 작성: 2026-09-25 (리나)
> 대상 게임: `com.Alioth.JusticeSchool.kr` (저스티스스쿨, Unity / IL2CPP, `libil2cpp.so` 기반)
> (구버전: `com.thumbage.heroes.google` / 아르메블랑쉐 — 기존 RVA 증거는 구버전 기준, 현버전 APK로 재검증 필요)

## 0. 한 줄 요약

> **규모가 큰 게임일수록 정적 분석보다 후킹(동적 분석)이 효율적이다.**
> 이 프로젝트는 후킹 포인트(함수명·RVA)가 이미 특정되어 있어,
> "어디를 찍을지"가 아니라 "어떻게 값을 빼올지"만 남았다.

## 1. 왜 후킹인가 — 이 프로젝트의 막힌 지점과 매핑

| 막힌 지점 | 정적 분석/PCAP의 한계 | 후킹으로 얻는 것 |
|---|---|---|
| 세션 키 (DH private) | PCAP만으로 복호화 불가 — 서버 개인키를 모름 | `DecryptUnSafe` 호출 직후를 찍으면 **키 없이 평문 OpInfo 직접 획득** |
| `Sign()` 알고리즘·signKey | 디컴파일만으로 서명 규칙 확정 어려움 | 호출 시 인자(`signKey`, `dict`)와 반환값을 그대로 캡처 |
| OpInfo 필드 매핑 | `OpCode = 2` 외 필드 할당 추적에 시간 소요 | `SendRequest.Login`·`ProccessRequestRes`에서 실제 할당값 확인 |
| param4 (344 bytes) 의미 | 생성 코드 추적 필요 | handshake 송신 함수를 찍어 생성 인자·호출 스택 확인 |
| HTTP 로그인 트랙 유효성 (TASK-007 §0) | 문자열 참조만으로 실제 호출 여부 판단 불가 | `V4_POST_Login` 호출 여부 = 트랙이 살아있는지의 직접 증거 |
| 0x40 압축 알고리즘 | decompress 함수 XREF 추적 필요 | 압축 전후 버퍼를 찍어 알고리즘 역추적 없이 입출력 확보 |

핵심 통찰: **후킹은 암호를 깨는 게 아니라, 암호가 풀린 지점을 관찰하는 것이다.**
`DecryptUnSafe`의 출력은 이미 평문이다. 키를 몰라도 된다.

## 2. 환경 전제

```text
LDPlayer (루팅 상태) ← 이미 사용 중인 환경
  └─ frida-server 실행 (에뮬레이터 아키텍처에 맞는 바이너리)
  └─ 호스트 PC에서 frida-tools / objection 등으로 스크립트 주입
```

- 대상 프로세스: 게임 앱 프로세스 (`com.Alioth.JusticeSchool.kr`)
- 대상 모듈: `libil2cpp.so` (네트워크·프로토콜 로직의 대부분이 여기 있음)
- 네이티브 네트워크 스택도 동일 프로세스 안에 있으므로, TLS pinning 이전 단계(평문)에서 가로채기 가능

## 3. 후킹 포인트 목록 (증거 기반)

우선순위 P0 = 로컬 서버 구현의 직접적인 블로커 해소.

### P0 — 복호화 지점 (세션키 병목 우회)

| 함수 | 근거 문서 | 후킹 목적 |
|---|---|---|
| `Alioth.S1.Net.Tools$$DecryptUnSafe()` | `research/CRYPTO_TRANSPORT.md` §4 | 입력(암호문+IV)과 출력(평문 OpInfo) 캡처. **세션키를 몰라도 평문 확보** |
| `DataTool$$DecryptUnSafe` | `CRYPTO_TRANSPORT.md` §4 (교차검증됨) | 위와 동일한 역할의 별도 경로 — 둘 다 찍어 커버리지 확보 |
| `Tools::.cctor` | `CRYPTO_TRANSPORT.md` §4 | 복호화 관련 정적 초기화 — 키/상수 테이블이 있으면 여기서 확인 |

### P0 — 핸드셰이크 송신 (param4 규명)

| 함수 | 근거 문서 | 후킹 목적 |
|---|---|---|
| TCP handshake 송신 함수 (`$$Handshake` 계열) | `CRYPTO_TRANSPORT.md` §2 | param4 344 bytes의 생성 인자·호출 스택 확인 (TASK-007 §7) |
| DH 키 생성 (`$$Secret`, `$$PublicKey` 계열) | `CRYPTO_TRANSPORT.md` §3 | 클라이언트 DH public #1/#2 생성 과정 확인 |

### P1 — 로그인 계약 (TASK-007)

| 함수 | RVA | 후킹 목적 |
|---|---|---|
| `ProtocolGame_HttpRequest.V4_POST_Login` | 0xCD5B48 | **호출 여부 자체가 TASK-007 §0의 답** (HTTP 트랙 유효성) |
| `ProtocolGame_HttpRequest.Sign(signKey, dict)` | 0xCD95C0 | 서명 알고리즘·signKey 출처·서명 대상 문자열 (TASK-007 §2) |
| `ProtocolGame_HttpRequest.GetDefaultParams()` | 0xCDBF58 | 기본 파라미터 전체 키 목록 (TASK-007 §1) |
| `ProtocolGame_HttpRequest.V3_POST_AllInOne` | 0xCDC5D0 | All-in-one bootstrap 요청 구조 |
| `ProtocolGame_HttpRequest.get_Token()` | 0xCD9534 | 토큰 획득 경로 |
| `ProtocolGame_SendRequest.Login()` | 0xCDE818 | OpInfo 필드 할당 전부 (TASK-007 §3) |
| `DataCenter.ProccessRequestRes` | (이름 기반 탐색) | 로그인 응답에서 읽는 필드·Player State 초기화 (TASK-007 §4) |

### P2 — 후순위 (필요 시)

| 대상 | 비고 |
|---|---|
| 0x40 decompress 함수 | XREF로 특정 후 후킹. 압축 전후 버퍼 캡처가 목적 |
| KCP handshake/송수신 | TCP 경로가 먼저 막혔을 때만 |
| `get_buildVerion()` (RVA 0xCD90BC) | 업데이트 게이트(TASK-002) 분석 시 |

## 4. IL2CPP 후킹 기법 노트

### 4.1 주소 계산

IL2CPP 게임은 심볼이 stripped된 경우가 많아 함수명 후킹이 안 될 수 있다.
이 프로젝트는 **RVA를 이미 확보**했으므로 주소 기반 후킹을 쓴다.

```text
후킹 주소 = libil2cpp.so 베이스 주소 + RVA
예: base + 0xCD95C0 → Sign()
```

Frida에서는 `Module.findBaseAddress('libil2cpp.so')`로 베이스를 구하고
`Interceptor.attach(base.add(0xCD95C0), {...})` 형태로 붙인다.
(Thumb/ARM64 모드 판별은 대상 아키텍처에 맞춰 처리 — LDPlayer는 보통 x86_64 또는 ARM64)

### 4.2 IL2CPP 함수 후킹 시 주의

- IL2CPP 함수는 인자가 `Il2CppObject*` 계열 포인터로 넘어온다.
  C# `string`·`Dictionary`는 그대로 읽히지 않고, IL2CPP API
  (`il2cpp_string_chars` 등) 또는 오프셋 파싱으로 내용을 꺼내야 한다.
- `DecryptUnSafe`처럼 `byte[]`를 다루는 함수는
  IL2CPP 배열 헤더 이후의 실제 버퍼 주소를 계산해서 덤프한다.
- 반환값 후킹(`onLeave`)에서 평문을 캡처하는 패턴이 이 프로젝트의 핵심이다:
  `onEnter`에서 인자(암호문·IV) 저장 → `onLeave`에서 반환값(평문) 덤프.

### 4.3 개념 스케치 (패턴 예시)

```javascript
// 패턴: 복호화 함수 입출력 캡처 (개념 스케치, 오프셋은 실측 후 확정)
const base = Module.findBaseAddress('libil2cpp.so');
Interceptor.attach(base.add(0xCD95C0 /* 예시 RVA */), {
  onEnter(args) {
    // args[0]=this, args[1..]=인자 — IL2CPP 호출 규약에 맞춰 파싱
    this.t0 = Date.now();
  },
  onLeave(retval) {
    // 반환값 덤프 → 평문/서명값 등 확보
  }
});
```

> 실제 스크립트는 대상 아키텍처·IL2CPP 버전의 호출 규약을 실측한 뒤 작성한다.
> 이 문서는 포인트 선정(어디를)과 목적(무엇을)에 집중한다.

## 5. 탐지(안티치트) 대응 개념

대규모 모바일 게임은 Frida 탐지를 포함할 수 있다. 대표적인 탐지 벡터와 대응 개념:

| 탐지 벡터 | 개념적 대응 |
|---|---|
| frida-server 기본 포트(27042) 스캔 | 포트 변경 또는 Gadget 모드(앱에 라이브러리 삽입 방식) |
| 프로세스명·라이브러리명 문자열 검사 | 바이너리명 변경, 문자열 난독화 |
| `ptrace` 기반 디버거 검출 | frida-server가 아닌 Gadget + spawn 방식 고려 |
| 무결성/서명 검사 | 후킹은 앱 바이너리를 수정하지 않으므로 일반적으로 무관 |

- 원칙: **탐지가 확인되기 전에는 과도한 우회를 먼저 하지 않는다.**
  일단 기본 frida-server로 붙여보고, 튕기거나 탐지 로그가 나오면 그때 대응한다.
- LDPlayer는 에뮬레이터라 실기기보다 탐지 내성이 낮은 편인 경우가 많다.

## 6. 하이브리드 워크플로우 (정적 분석 + 후킹)

```text
Ghidra/디컴파일 (정적)
  → 후킹 포인트 선정 (RVA·함수명) — 이 문서 §3
  → Frida 후킹 (동적)
  → 실제 값 캡처 (평문 OpInfo, 서명값, 파라미터)
  → research/contracts/*.md 에 계약으로 기록
  → local-server/ 구현에 반영
  → 런타임 검증
```

정적 분석은 "어디를 볼지"를, 후킹은 "실제 값이 무엇인지"를 담당한다.
둘 중 하나만으로는 막히는 지점(TASK-007 항목들)이 이 조합으로는 풀린다.

## 7. TASK 연결표

| TASK | 후킹 기여 |
|---|---|
| TASK-007 §0 (HTTP 트랙 유효성) | `V4_POST_Login` 호출 여부로 직접 판정 |
| TASK-007 §1·§2 (파라미터·Sign) | 인자 캡처로 확정 |
| TASK-007 §3·§4 (OpInfo·응답 파싱) | 필드 할당/읽기 실측 |
| TASK-007 §5 (0x40 압축) | 압축 전후 버퍼 캡처 |
| TASK-007 §7 (param4) | 생성 호출 스택 확인 |
| TASK-006 (Login 계약) | 위 결과를 contracts/AUTH.md에 반영 |
| TASK-002 (Update Gate) | `get_buildVerion`·버전 체크 요청 후킹 (필요 시) |

## 8. 주의사항

- 본인이 보유·분석 권한을 가진 앱·계정·테스트 환경에서만 수행한다.
- 인증정보 탈취, 타인 계정 접근, 서버 인증 우회, 제3자 서비스의 접근제어 회피를 목적으로 사용하지 않는다.
  (기존 `최초개요-req_rsp_수집/05_해독_정확도.md`의 주의사항과 동일)
- 캡처된 토큰·세션값은 저장소에 평문으로 남기지 않는다 (수집 규격 02 문서 §4 참조).

## 9. 관련 문서

- `research/CRYPTO_TRANSPORT.md` — 복호화 지점·핸드셰이크 증거
- `research/targets/TASK-007.md` — 후킹으로 해소할 잔여 항목
- `research/targets/INDEX.md` — 전체 TASK 상태
- `최초개요-req_rsp_수집/05_해독_정확도.md` — 기존 후킹/Ru
...[truncated 216 chars]