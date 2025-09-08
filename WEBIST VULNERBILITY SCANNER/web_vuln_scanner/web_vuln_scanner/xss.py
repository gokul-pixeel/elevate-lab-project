
import copy
import requests
import urllib.parse as up
from requests.exceptions import RequestException

TIMEOUT = 8

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "/><svg/onload=alert(1)>",
    "';alert(1);//",
]

def reflect_present(body, payload):
    if not body:
        return False
    b = body.lower()
    enc = payload.replace("<", "&lt;").replace(">", "&gt;").lower()
    return (payload.lower() in b) or (enc in b)

def test_params(url):
    vulns = []
    parsed = up.urlparse(url)
    qs = up.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return vulns
    base = parsed._replace(query="").geturl()
    for key in qs.keys():
        for payload in XSS_PAYLOADS:
            mutated = copy.deepcopy(qs)
            mutated[key] = [payload]
            qstr = up.urlencode(mutated, doseq=True)
            test_url = base + "?" + qstr
            try:
                r = requests.get(test_url, timeout=TIMEOUT)
                if r and reflect_present(r.text, payload):
                    vulns.append({"type": "xss", "vector": "param", "url": test_url, "evidence": "reflection"})
            except RequestException:
                continue
    return vulns

def submit_form(base_url, form, payload):
    action = form.get("action") or ""
    method = (form.get("method") or "GET").upper()
    target = up.urljoin(base_url, action)
    data = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
        data[name] = payload if inp.get("type") not in ("submit", "button") else inp.get("value", "")
    try:
        if method == "POST":
            r = requests.post(target, data=data, timeout=TIMEOUT)
        else:
            r = requests.get(target, params=data, timeout=TIMEOUT)
        return target, r
    except RequestException:
        return target, None

def test_forms(base_url, forms):
    vulns = []
    for form in forms:
        for payload in XSS_PAYLOADS:
            target, r = submit_form(base_url, form, payload)
            if r and reflect_present(r.text, payload):
                vulns.append({"type": "xss", "vector": "form", "url": target, "evidence": "reflection"})
    return vulns
