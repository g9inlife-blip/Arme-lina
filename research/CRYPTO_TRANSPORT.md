# Crypto / Transport — 확정 증거 정리

> 작성: 2026-09-25 (리나)
> 근거: `최초개요-req_rsp_수집/PCAP/` 2026-09-21/22 분석 문서 4건 + `pcap_analyzer.py`
>
> 이 문서는 research/의 canonical 암호화 정리다. 세부 decompile/어셈블리 증거는
> 원본 문서(`DH64_암호화_연산_분석.md`, `DH64_암호화_연산_분석_코드.md`,
> `TCP_DH64_키생성_분석_2026-09-22.md`, `PCAP_DH_실행_기록_분석_2026-09-22.md`)를 참조한다.

## 1. 한 줄 결론

게임 서버 통신(`*:8000`, TCP+UDP/KCP)의 application payload는 평문이 아니다.

```text
DH64 (g=5, p=2^64-59) 이중 DH
  → 16-byte session key
  → RijndaelManaged CBC / PKCS7 / 128-bit block
  → payload = [16-byte IV][ciphertext]
  → 복호화 후 0x40 flag면 decompress
  → protobuf OpInfo deserialize
```

이 체인은 Ghidra 코드 분석과 실제 PCAP 양쪽에서 교차검증됐다.

## 2. DH64 — CONFIRMED

| 항목 | 값 | 근거 |
|---|---|---|
| 클래스 | `Alioth.S1.Common.DH64` | dump.cs / Ghidra |
| generator | `g = 5` | `PublicKey()` → `powmodp(5, private)` |
| modulus | `p = 2^64 - 59` (`0xFFFFFFFFFFFFFFC5`) | ARM64 `mov x9,#-0x3B` 해석 |
| private 생성 | `((uint64)R1 << 32) \| ((uint32)R2 + 1)` | `System.Random` 2회 호출 조합 |
| public 계산 | `5^private mod p` | `DH64$$PublicKey` |
| secret 계산 | `peerPublic^localPrivate mod p` | `DH64$$Secret` → `powmodp` |
| 수행 횟수 | 2회 (keypair #1, #2) | `TCPTube$$Update`, `KCPTube$$Handshake1` |
| session key | `LE64(secret1) \|\| LE64(secret2)` = 16 bytes | `TCPTube + 0x38` key buffer |

> 정정 기록: 초기 분석에서는 `p = 59`로 해석했으나, ARM64 연산(`-0x3B`의 64-bit 해석)과
> PCAP의 64-bit public 값 대조로 `p = 2^64 - 59`로 정정됐다.

`DH64$$Secret`의 확인된 호출자:
- `Alioth.S1.Net.KCPTube$$Handshake2`
- `Alioth.S1.Net.TCPTube$$TryOutput`

## 3. TCP Handshake wire layout — CONFIRMED (PCAP 대조 완료)

### Client → Server

| Offset | Size | 의미 |
|---|---|---|
| 0x00 | 8 | zero |
| 0x08 | 4 | handshake length (관측: `0x169` = 361) |
| 0x0C | 1 | marker = 1 |
| 0x0D | 8 | client DH public #1 |
| 0x15 | 8 | client DH public #2 |
| 0x1D | N | param4 (관측: 344 bytes, Base64 형태 → decode 시 256 bytes) |

관측 크기: `8 + 4 + 1 + 8 + 8 + 344 = 373` bytes — PCAP 실측과 정확히 일치.

### Server → Client

| Offset | Size | 의미 |
|---|---|---|
| 0x00 | 8 | reserved / zero |
| 0x08 | 4 | length (정상 handshake: `0x19`) |
| 0x0C | 1 | marker = 1 |
| 0x0D | 8 | TCPConvID (관측: `0x632`) |
| 0x15 | 8 | server DH public #1 |
| 0x1D | 8 | server DH public #2 |

### KCP Handshake

동일한 DH64 개념, wire layout만 다름.
- `KCPTube$$Handshake1`: public #1/#2를 패킷 `+0x08`/`+0x10`에 기록
- `KCPTube$$Handshake2`: 상대 패킷 `+0x11`/`+0x19`에서 peer public 읽기 → `Secret()` 계산
- PCAP에서 양방향 KCP public 값 교환 확인됨

### param4 (UNKNOWN)

client handshake `0x1D` 이후 344 bytes는 Base64 형태(256 bytes binary)다.
RSA-2048 ciphertext와 크기가 유사하지만 **RSA 사용으로 확정하지 않는다**.
로그인/인증 관련 handshake parameter일 가능성이 있어 별도 조사가 필요하다.

## 4. Frame / 암호화 — CONFIRMED

### Flags

| Flag | 의미 |
|---|---|
| `0x80` | Encrypt |
| `0x40` | Compress |

### 암호화 payload 구조

```text
+----------------+---------------------------+
| IV 16 bytes    | Rijndael CBC ciphertext   |
+----------------+---------------------------+
```

- ciphertext는 16-byte block 정렬됨 (관측: 176 bytes = 11 blocks, 192 bytes = 12 blocks)

### Rijndael 설정 — CONFIRMED

`Tools::.cctor` + `RijndaelManagedTransform::.ctor` + `DataTool$$DecryptUnSafe` 교차검증:

| 항목 | 값 |
|---|---|
| Key | 16 bytes (DH64 session key) |
| BlockSize | 128 bits (16 bytes) |
| Mode | CBC (`= 1`) |
| Padding | PKCS7 (`= 2`) |
| FeedbackSize | 128 bits |
| IV | encrypted payload 앞 16 bytes |

### 복호화 흐름 — CONFIRMED

`Alioth.S1.Net.Tools$$DecryptUnSafe(encrypted, key, outputStream)`:

```text
encrypted input
  ↓
IV = input[0:16], ciphertext = input[16:]
  ↓
CreateDecryptor(key, IV)
  ↓
TransformBlock × N (0x10 단위)
  ↓
TransformFinalBlock (PKCS7 처리)
  ↓
MemoryStream → plaintext
  ↓
Dispose
```

`DataTool$$DecryptUnSafe()`는 매번 새 `RijndaelManaged`를 생성하지만 동일한 규칙 — 교차검증됨.

### 복호화 이후

```text
plaintext
  ↓
0x40 flag? → decompress (알고리즘 미확정)
  ↓
protobuf OpInfo deserialize
  ↓
Request / Response 처리
```

## 5. PCAP 교차검증 — CONFIRMED (2026-09-21, 211 packets)

- `TCP 10.215.173.1:39490 ↔ 182.92.62.79:8000`
- `UDP 10.215.173.1:33922 ↔ 182.92.62.79:8000` (KCP)
- client TCP handshake 373 bytes = Ghidra layout과 정확히 일치
- server 응답에서 TCPConvID + server DH public #1/#2 확인
- application payload에서 `[16-byte IV][ciphertext]` 반복 관측
- handshake/framing metadata는 평문, application payload는 암호화

도구: `최초개요-req_rsp_수집/PCAP/pcap_analyzer.py` (표준 Python만 사용, TCP 재조립/DH 추출/암호화 payload 탐지)

## 6. 아직 UNKNOWN인 것

우선순위 순:

1. **Runtime 16-byte session key 확보** — 실행 중 `CreateDecryptor(key, IV)` 호출 시점 또는 `TCPTube`/`KCPTube` key buffer에서 확보해야 실제 복호화 검증 가능. PCAP의 public 값만으로는 private을 복구할 수 없으므로 이것이 다음 단계의 핵심 병목이다.
2. **실제 PCAP 복호화 검증** — key 확보 후 IV + ciphertext → plaintext 연결 확인.
3. **0x40 compression 알고리즘** — 미확정.
4. **protobuf OpInfo 필드 매핑 / OperationCode 목록** — `OperationCode.Login = 2` 외 미정리.
5. **client handshake param4 (344 bytes)** — 의미 미확정.
6. **KCP fragment 완전 재조립** — `pcap_analyzer.py`에 미구현.

## 7. Local Server 구현에 주는 의미

이 증거가 확정된 이상, Local Server의 게임 서버(`:8000`) 종단은 다음을 구현해야 한다:

```text
1. Client TCP handshake 수신 → layout 파싱
2. Server handshake 응답 (TCPConvID + server DH public #1/#2)
3. DH secret 계산 → 16-byte session key (서버도 자신의 keypair 생성)
4. 이후 frame: [IV][Rijndael-CBC-PKCS7 ciphertext] 로 OpInfo 송수신
5. OpInfo = protobuf → OperationCode별 handler
```

즉 **원본 wire format을 그대로 구현하는 것이 가능**하며, Client의 crypto/transport를 뜯어고칠 필요가 없다
(COMMON_RULES §2 Level 1 — Original Wire/TLS Compatibility 가설을 지지하는 증거).

### 7.1 로컬 서버 구현 관점에서의 중요 구분

1. **"세션 키 런타임 캡처" 병목은 도청에만 해당한다.**
   §6의 병목(원본 서버의 DH private key를 알 수 없어 PCAP 복호화 불가)은
   **원본 서버 트래픽을 엿듣는 경우**의 문제다.
   로컬 서버는 handshake 응답 시 **서버측 DH keypair를 직접 생성**하므로
   session key를 온전히 계산할 수 있다. 로컬 서버 구현에는 병목이 없다.

2. **param4 (344 bytes)는 수신 후 무시해도 될 가능성이 높다.**
   param4는 client→server 방향 페이로드이며, 서버 응답에 param4 기반 값이
   들어간다는 증거는 없다. 로컬 서버는 파싱 위치만 맞추고 내용은 버리는
   전략으로 시작해도 된다 (클라이언트가 param4 echo를 요구한다는 증거가
   나오면 그때 대응 — TASK-007 §7).

3. **구현 순서는 TCP부터.**
   PCAP에 TCP와 UDP/KCP가 모두 보이지만, 로그인은 TCP 경로로 먼저 구현하고
   KCP는 필요해지면 추가한다. KCP fragment 재조립 미구현도 TCP 우선 전략이면
   당장 문제가 되지 않는다.

단, HTTP API (`ac.aliother.com:443`, `API_Login` 등)의 서명/직렬화는 별개 트랙으로 아직 미확정이다
→ TASK-007 참조. 단 해당 트랙이 현재 클라이언트에 여전히 살아있는지는 먼저 검증 필요 (TASK-007 §0).

## 8. 원본 문서

- `최초개요-req_rsp_수집/PCAP/DH64_암호화_연산_분석.md`
- `최초개요-req_rsp_수집/PCAP/DH64_암호화_연산_분석_코드.md`
- `최초개요-req_rsp_수집/PCAP/TCP_DH64_키생성_분석_2026-09-22.md`
- `최초개요-req_rsp_수집/PCAP/PCAP_DH_실행_기록_분석_2026-09-22.md`
- `최초개요-req_rsp_수집/PCAP/PCAP_분석_결과_비교_방법론.md`
