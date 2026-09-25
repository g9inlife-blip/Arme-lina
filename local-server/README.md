# Local Private Server (DRAFT)

> 상태: **DRAFT** — TASK-006의 정적 증거를 기반으로 한 계약 초안.
> `research/reports/TASK-006-result.md` §7의 미확정 항목(URL path, 서명 알고리즘,
> 직렬화 형식)이 확정되기 전까지 실제 클라이언트 연결을 시도하지 않는다.

## 구조

```text
local-server/
├── README.md            # 이 문서
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI 엔트리포인트
│   ├── config.py        # 서버 주소/포트/버전 상수
│   ├── db.py            # SQLite 연결 + 스키마 초기화
│   ├── state.py         # Player State 접근 레이어 (DRAFT)
│   └── routes/
│       ├── __init__.py
│       ├── allin1.py    # API_Allin1  (부트스트랩)
│       ├── anon.py      # API_Anon    (게스트 계정)
│       └── login.py     # API_Login   (로그인 토큰)
└── data/
    └── player.db        # 실행 시 생성 (git 제외)
```

## 실행

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

## 계약 출처

모든 Response 필드는 `research/reports/TASK-006-result.md` §3.4–§3.5의
`Response_GetLoginToken` / `Response_Account_Anon` / `Response_Allin1`
정적 증거에서 가져왔다. 필드 추가/삭제는 역분석 증거 없이 하지 않는다.

## 아직 모르는 것 (구현 전 필수)

1. `API_Login`의 실제 HTTP URL path
2. `Sign(signKey, dict)` 알고리즘과 키 출처
3. Request body 직렬화 형식 (JSON / form / 기타)
4. 게임 서버(`*:8000`) TCP 핸드셰이크 구조 — 별도 구현 필요
