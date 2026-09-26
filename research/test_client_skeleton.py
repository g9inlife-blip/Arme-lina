#!/usr/bin/env python3
"""
JusticeSchool 로그인 테스트 클라이언트 (스켈레톤)

목적: V4_POST_Login API의 요청을 재현하기 위한 테스트 클라이언트
상태: Sign 알고리즘 미확정 → sign() 함수는 플레이스홀더

사용법:
    1. Frida 캡처로 Sign 알고리즘을 확정
    2. sign() 함수를 실제 구현으로 교체
    3. python3 test_client.py --app-key <KEY> --username <ID> --password <PW>

참고: research/reports/NEWVERSION-003-params.md
"""

import argparse
import hashlib
import json
import sys
import urllib.request
import urllib.parse

# 게임 서버 (확정 필요 - Frida 또는 패킷 캡처로 확인)
BASE_URL = "https://ac.aliother.com"  # 예시, 실제 URL은 캡처로 확정

# API 이름 (확정 필요)
API_LOGIN = "login"  # apiName 파라미터, 실제 값은 캡처로 확정


def sign(content: str, api_name: str) -> str:
    """
    Sign(content, apiName) -> 서명 문자열
    
    TODO: Frida 캡처 로그를 분석하여 실제 알고리즘으로 교체
    
    가설 (검증 필요):
    - MD5(content + apiName + secret_key)?
    - HMAC-SHA256?
    - 커스텀 알고리즘?
    
    Frida 로그 형식:
        [Sign] content="...", apiName="..." -> "..."
    이 입출력 쌍을 보고 패턴을 역산
    """
    raise NotImplementedError(
        "Sign 알고리즘이 아직 확정되지 않았습니다. "
        "Frida 캡처 후 이 함수를 구현하세요."
    )


def get_default_params() -> dict:
    """
    GetDefaultParams() -> 기본 파라미터 딕셔너리
    
    TODO: Frida로 실제 반환값 캡처 후 구현
    예상 키: platform, version, device_id, language 등
    """
    # 플레이스홀더 - Frida 캡처로 확정
    return {
        # "platform": "android",
        # "version": "1.0.0",
        # ...
    }


def v4_post_login(app_key: str, content: str, api_name: str) -> dict:
    """
    V4_POST_Login(app_key, content, apiName)
    
    실제 HTTP 요청을 구성하고 전송
    """
    # 1. 서명 생성
    signature = sign(content, api_name)
    
    # 2. 요청 본문 구성
    # 실제 형식은 Frida 캡처로 확정 (JSON? form-data?)
    body = {
        "app_key": app_key,
        "content": content,
        "apiName": api_name,
        "sign": signature,
    }
    
    # 3. 기본 파라미터 병합
    body.update(get_default_params())
    
    # 4. HTTP POST
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/{api_name}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def build_login_content(username: str, password: str) -> str:
    """
    로그인용 content JSON 구성
    
    TODO: Frida로 실제 content 구조 캡처 후 구현
    예상: {"username": "...", "password": "...", ...}
    """
    # 플레이스홀더
    content_data = {
        "username": username,
        "password": password,
        # 추가 필드는 캡처로 확정
    }
    return json.dumps(content_data, separators=(",", ":"))


def main():
    parser = argparse.ArgumentParser(description="JusticeSchool 로그인 테스트")
    parser.add_argument("--app-key", required=True, help="앱 키")
    parser.add_argument("--username", required=True, help="로그인 ID")
    parser.add_argument("--password", required=True, help="비밀번호")
    parser.add_argument("--api-name", default=API_LOGIN, help="API 이름")
    args = parser.parse_args()
    
    print(f"[*] content 구성 중...")
    content = build_login_content(args.username, args.password)
    print(f"    content: {content[:100]}...")
    
    print(f"[*] 로그인 요청 전송 중... (apiName={args.api_name})")
    try:
        result = v4_post_login(args.app_key, content, args.api_name)
        print(f"[+] 응답:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except NotImplementedError as e:
        print(f"[!] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
