# Frida 관련 파일

JusticeSchool (`com.Alioth.JusticeSchool.kr`) 동적 분석용 Frida 스크립트 모음.

## 파일 목록

| 파일 | 설명 |
|------|------|
| `justice_hook.js` | 로그인/Sign 후킹 스크립트 v2 |

## 사용법

### 준비물
- PC (Windows/Linux/Mac)
- Frida (`pip install frida-tools`)
- `frida-il2cpp-bridge` (`npm install frida-il2cpp-bridge`)
- 루팅된 Android 기기 또는 에뮬레이터
- USB 디버깅 활성화

### 실행

```bash
# 1. Frida 서버를 기기에서 실행
adb push frida-server /data/local/tmp/
adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 2. 스크립트 실행
frida -U -f com.Alioth.JusticeSchool.kr -l justice_hook.js --no-pause
```

### 캡처할 로그

`[SIGN_DATA]`로 시작하는 줄이 핵심:
```
[SIGN_DATA] input_content="..." input_apiName="..." output="..."
```

이 입출력 쌍을 모아서 Sign 알고리즘을 역산한다.

## 후킹 대상

`ProtocolGame_HttpRequest` 클래스의 메서드:
- `V4_POST_Login(app_key, content, apiName)` - 로그인 요청
- `Sign(content, apiName)` - 서명 생성 (가장 중요)
- `GetDefaultParams()` - 기본 파라미터
- `V3_POST_AllInOne(app_key)` - 통합 API

## 참고

- 상세 분석: `../reports/NEWVERSION-002-sign-analysis.md`
- 파라미터 목록: `../reports/NEWVERSION-003-params.md`
- 로그인 스펙: `../reports/NEWVERSION-004-login-spec.md`
