
import time
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
from utils import normalize_url, same_domain, is_http_url, unique, info, warn

CRAWL_MAX_PAGES = 60
CRAWL_MAX_DEPTH = 2
REQUEST_TIMEOUT = 8
REQUEST_DELAY = 0.2

def fetch(url):
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return r
    except RequestException:
        return None

def parse_links(base_url, html):
    links = []
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = normalize_url(base_url, href)
        if is_http_url(full) and same_domain(base_url, full):
            links.append(full.split("#")[0])
    return unique(links)

def extract_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "GET").upper()
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            value = inp.get("value") or ""
            inputs.append({"name": name, "type": itype, "value": value})
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms

def crawl(start_url):
    queue = [(start_url, 0)]
    visited = set()
    pages = []
    forms_map = {}
    while queue and len(pages) < CRAWL_MAX_PAGES:
        url, depth = queue.pop(0)
        if url in visited or depth > CRAWL_MAX_DEPTH:
            continue
        visited.add(url)

        r = fetch(url)
        if not r or not r.text:
            warn(f"Skip (no response): {url}")
            continue
        pages.append(url)
        html = r.text
        forms_map[url] = extract_forms(html)

        links = parse_links(url, html)
        info(f"Crawled {url} -> {len(links)} links, {len(forms_map[url])} forms")
        for l in links:
            if l not in visited and same_domain(start_url, l):
                queue.append((l, depth + 1))
        time.sleep(REQUEST_DELAY)
    return pages, forms_map
