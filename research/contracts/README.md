# Contract Registry

> 근거 문서: `research/PROTOCOL_CAPTURE_AND_CRYPTO_WORKFLOW.md` §10

기능별 Request/Response 계약을 누적하는 레지스트리다.
모든 항목은 `CONFIRMED / PROBABLE / UNKNOWN` 신뢰도로 관리한다.

## 파일 구성

| 파일 | 기능 |
|---|---|
| `AUTH.md` | 로그인/계정/부트스트랩 |
| `PLAYER.md` | 플레이어 상태 조회/갱신 |
| `SHOP.md` | 상점 |
| `DUNGEON.md` | 던전 |
| `BATTLE.md` | 전투 |
| `GACHA.md` | 가챠 |
| `MISSION.md` | 미션/업적 |
| `EVENT.md` | 이벤트/출석/우편 |

## Contract 작성 규격

```text
Action:
Endpoint/Command:
Transport: (HTTP API / Game Server :8000)
Request Type / Fields:
Response Type / Fields:
Serializer:
Encryptor:
Decryptor:
Deserializer:
Client Handler:
State Effect:
Persistence Effect:
Success Code / Failure Code:
Evidence: (PCAP / XREF / decompile / runtime)
Confidence: CONFIRMED / PROBABLE / UNKNOWN
Runtime Verified: yes / no
Next API Dependency:
```

## 규칙

- Raw PCAP/암호문을 그대로 붙이지 않는다. 정규화된 계약만 기록한다.
- Client static data만으로 발견한 ID는 서버 authoritative 값과 동일하다고 단정하지 않는다.
- Response 수신 사실과 State 변경 사실을 분리해서 기록한다.
- `success=true`만으로 기능 완료를 확정하지 않는다.
