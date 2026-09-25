# Heroes Offline Research

이 저장소는 `com.Alioth.JusticeSchool.kr` (저스티스스쿨) Unity/IL2CPP 게임의 역분석 작업용 연구 저장소다.
(구버전: `com.thumbage.heroes.google` / 아르메블랑쉐 — 기존 증거는 구버전 기준, `research/CURRENT_STATE.md` §0 참조)

## 현재 방향 (2026-09-25 기준)

**Local Private Server / API Emulation** — 원본 서버 전체를 복제하는 것이 아니라,
원본 Client가 기대하는 Request/Response 계약을 유지하면서 서버가 담당하던
Player State와 게임 서비스를 Local Server + SQLite로 제공한다.

완전 Client Local화는 기본 방향이 아니다 (필요한 기능에만 Hybrid로 허용).

상세: `research/ARCHITECTURE_DIRECTION.md`, `research/COMMON_RULES.md`

## 역할 분담
- **GPT**: 분석 방향 결정, 가설 수립, 증거 해석, 다음 조사 TASK 정의.
- **Codex**: 로컬 APK/Ghidra/ADB를 실제로 조작하고, 조사 결과를 문서화하며 필요할 때만 파일을 수정/빌드.
- **리나 (Muse)**: 저장소 정리/문서 분석/재정립, Local Server 스캐폴드 등 VM에서 가능한 작업.
- **사용자**: 수정 APK를 실제 실행하고 화면/로그 결과를 알려줌.

## 저장 원칙
Git에는 거대한 원본 바이너리를 넣지 않는다.
- 저장하지 않음: APK, `libil2cpp.so`, `global-metadata.dat`, Ghidra 프로젝트, 대형 dump/json
- 저장함: TASK, decompile 핵심 구간, XREF/call graph 요약, 문자열 증거, 패치 명세, 빌드/런타임 결과, 현재 상태

## 기본 루프
1. GPT가 `research/targets/TASK-xxx.md` 작성/지시
2. Codex가 로컬 Ghidra/ADB에서 **조사만 수행**
3. Codex가 `research/reports/TASK-xxx-result.md` 작성 후 push
4. GPT가 결과를 읽고 다음 조사 지점 결정
5. 증거가 충분해지면 PATCH 문서 작성
6. Codex가 패치/빌드/자동 검증
7. 사용자가 APK를 실행하고 결과 전달

## 현재 핵심 목표
Login → Main Menu 계약을 확정하고 최소 Local Server로 실제 연결한다.

- 전송/암호화: 확정 (`research/CRYPTO_TRANSPORT.md`)
- 다음 조사: HTTP 로그인 API + OpInfo/State (`research/targets/TASK-007.md`)

시작점과 주요 조사 대상은 `research/START_HERE.md`, `research/CURRENT_STATE.md`를 참조한다.
TASK 상태는 `research/targets/INDEX.md`를 참조한다.
