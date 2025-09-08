
import time
import urllib.parse as up
from colorama import Fore, Style, init

init(autoreset=True)

def normalize_url(base, link):
    return up.urljoin(base, link)

def same_domain(u1, u2):
    try:
        n1 = up.urlparse(u1).netloc.split(':')[0].lower()
        n2 = up.urlparse(u2).netloc.split(':')[0].lower()
        return n1 == n2 and n1 != ""
    except Exception:
        return False

def is_http_url(u):
    try:
        p = up.urlparse(u).scheme
        return p in ("http", "https")
    except Exception:
        return False

def unique(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def short(s, n=120):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."

def banner(text):
    print(Fore.CYAN + Style.BRIGHT + f"\n=== {text} ===" + Style.RESET_ALL)

def info(text):
    print(Fore.WHITE + "[*] " + text)

def good(text):
    print(Fore.GREEN + "[+] " + text)

def warn(text):
    print(Fore.YELLOW + "[!] " + text)

def bad(text):
    print(Fore.RED + "[-] " + text)

class Timer:
    def __init__(self):
        self.t0 = time.time()
    def stop(self):
        return time.time() - self.t0
