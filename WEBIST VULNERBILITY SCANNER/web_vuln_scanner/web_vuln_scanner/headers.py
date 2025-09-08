
import requests
from requests.exceptions import RequestException

TIMEOUT = 8

RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check(url):
    missing = []
    present = {}
    try:
        r = requests.get(url, timeout=TIMEOUT)
        hdrs = r.headers or {}
        for h in RECOMMENDED_HEADERS:
            if h in hdrs:
                present[h] = hdrs.get(h)
            else:
                missing.append(h)
    except RequestException:
        missing = RECOMMENDED_HEADERS[:]
    return present, missing
