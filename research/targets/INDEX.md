# TASK Index

> 최종 업데이트: 2026-09-25 (리나)

## 상태 요약

| TASK | 제목 | 상태 | 비고 |
|---|---|---|---|
| TASK-001 | 실제 Scene 전환 경로 증명 | SUPERSEDED | Local Server 방향 전환 후 우선순위 상실. 필요 시 TASK-006 하위로 재정의 |
| TASK-002 | GameUpdateService 온라인 게이트 구조화 | PLANNED | Phase 0 (Update Gate) — 아키텍처상 여전히 유효 |
| TASK-003 | 로그인 → 메인 메뉴 데이터 흐름 및 온라인 의존성 증명 | SUPERSEDED | TASK-006이 현재 방향(Local Server)에 맞게 계승. 구 "오프라인" 어휘로 작성됨 |
| TASK-004 | Unity Asset / AssetBundle 구조 조사 | DEFERRED | 오프라인 동작 기반 확보 이후 실행 — 조건 미충족 |
| TASK-005 | Request → Local Response → Player State / Static Data 구조 증명 | PLANNED | TASK-006 이후 단계. 일부 "오프라인" 어휘 정 필요 |
| TASK-006 | Login API Contract / Local Server Bootstrap 조사 | IN PROGRESS | 현재 최전선. §7 미확정 항목 중 crypto 부분은 `CRYPTO_TRANSPORT.md`로 해소됨 |
| TASK-007 | Login HTTP + OpInfo + 압축/프로토콜 잔여 증거 확보 | DEFINED | 2026-09-25 개정. 핸드셰이크/DH/Rijndael 제외 (확정됨) |

## 상태 정의

- `DEFINED` — 목표/범위가 문서화됐고 실행 대기 중
- `PLANNED` — 실행 조건이 명시된 계획 단계
- `IN PROGRESS` — 조사 진행 중, 결과 보고서 작성 중
- `DEFERRED` — 조건 충족 시까지 보류
- `SUPERSEDED` — 다른 TASK가 계승. 새로 시작하지 않음
- `DONE` — 증거와 함께 종료, 보고서 존재

## 결과 보고서

| 보고서 | 상태 |
|---|---|
| `research/reports/TASK-006-result.md` | IN PROGRESS (2026-09-25 보충 섹션 추가됨) |

## 다음 실행 순서 (현재 기준)

```text
TASK-007 (HTTP 로그인 + OpInfo + 압축)
  → TASK-006 완료 (Login → Main 계약 확정)
  → TASK-002 (Update Gate — 필요 시)
  → TASK-005 (기능별 State 구조)
  → TASK-004 (Asset — DEFERRED 유지)
```
