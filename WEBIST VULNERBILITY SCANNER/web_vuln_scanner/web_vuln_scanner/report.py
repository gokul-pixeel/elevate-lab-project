
import os
import datetime
from utils import short

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    return p

def html_escape(s):
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            )

def sev_badge(vtype):
    if vtype == "sqli":
        return '<span style="background:#c62828;color:white;padding:2px 6px;border-radius:6px">High</span>'
    if vtype == "xss":
        return '<span style="background:#ef6c00;color:white;padding:2px 6px;border-radius:6px">Medium</span>'
    return '<span style="background:#607d8b;color:white;padding:2px 6px;border-radius:6px">Info</span>'

def generate_html(target, pages, vulns, headers_present, headers_missing, duration_s):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for v in vulns:
        badge = sev_badge(v.get("type"))
        rows.append(f"<tr><td>{html_escape(v.get('type'))}</td>"
                    f"<td>{html_escape(v.get('vector'))}</td>"
                    f"<td><a href='{html_escape(v.get('url'))}' target='_blank'>{html_escape(short(v.get('url'), 100))}</a></td>"
                    f"<td>{html_escape(v.get('evidence'))}</td>"
                    f"<td>{badge}</td></tr>")
    hdr_rows = []
    for k, val in (headers_present or {}).items():
        hdr_rows.append(f"<tr><td>{html_escape(k)}</td><td>{html_escape(val)}</td><td>Present</td></tr>")
    for k in (headers_missing or []):
        hdr_rows.append(f"<tr><td>{html_escape(k)}</td><td>-</td><td style='color:#c62828'>Missing</td></tr>")

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Scan Report - {html_escape(target)}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:24px;}}
h1{{margin-bottom:0}}
.small{{color:#666;margin-top:4px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px}}
th{{background:#f5f5f5}}
.code{{font-family:ui-monospace,Consolas,monospace}}
.badge{{display:inline-block;padding:2px 6px;border-radius:6px;background:#eee}}
</style>
</head>
<body>
<h1>Web Application Vulnerability Scan</h1>
<div class="small">Target: <span class="code">{html_escape(target)}</span> • Pages crawled: {len(pages)} • Findings: {len(vulns)} • Duration: {duration_s:.1f}s • Generated: {ts}</div>

<h2>Findings</h2>
<table>
<tr><th>Type</th><th>Vector</th><th>Location</th><th>Evidence</th><th>Severity</th></tr>
{''.join(rows) if rows else '<tr><td colspan="5">No issues detected by automated checks.</td></tr>'}
</table>

<h2>Security Headers</h2>
<table>
<tr><th>Header</th><th>Value</th><th>Status</th></tr>
{''.join(hdr_rows) if hdr_rows else '<tr><td colspan="3">No header data.</td></tr>'}
</table>

<h2>Scope</h2>
<ul>
<li>Pages crawled ({len(pages)}): <div class="code">{'<br>'.join(html_escape(p) for p in pages)}</div></li>
<li>Techniques: SQL Injection (basic), Reflected XSS (basic), Header audit</li>
</ul>

<p class="small">Disclaimer: Automated scanners can miss issues or report false positives. Validate findings manually.</p>
</body>
</html>"""
    return html

def write_report(target, pages, vulns, headers_present, headers_missing, duration_s):
    out_dir = ensure_dir("reports")
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(out_dir, f"scan-{ts}.html")
    html = generate_html(target, pages, vulns, headers_present, headers_missing, duration_s)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
