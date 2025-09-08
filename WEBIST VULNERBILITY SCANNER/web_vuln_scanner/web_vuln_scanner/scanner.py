
import sys
import validators
from utils import banner, info, good, warn, bad, Timer
from crawler import crawl
from sqli import test_params as sqli_params, test_forms as sqli_forms
from xss import test_params as xss_params, test_forms as xss_forms
from headers import check as headers_check
from report import write_report

SAFE_DEMOS = [
    "http://testphp.vulnweb.com/",
    "https://demo.testfire.net/",
    "https://juice-shop.herokuapp.com/"
]

def prompt_target():
    banner("Target Selection")
    print("Enter a target URL (e.g., https://example.com)")
    print("Or choose a demo target:")
    for i, d in enumerate(SAFE_DEMOS, 1):
        print(f"  {i}. {d}")
    url = input("\nTarget URL (or 1/2/3): ").strip()
    if url in ("1", "2", "3"):
        url = SAFE_DEMOS[int(url)-1]
    if not url.startswith("http"):
        url = "http://" + url
    if not validators.url(url):
        bad("That doesn't look like a valid URL.")
        sys.exit(1)
    return url

def prompt_output_mode():
    banner("Output Mode")
    print("Choose how you want results:")
    print("  1) Console only")
    print("  2) HTML report (default)")
    print("  3) Both console + HTML report")
    choice = input("Enter 1/2/3 [default: 2]: ").strip()
    if choice not in ("1","2","3",""):
        warn("Unknown choice, defaulting to 2")
        choice = "2"
    if choice == "":
        choice = "2"
    return choice

def run():
    banner("Web Application Vulnerability Scanner")
    target = prompt_target()
    mode = prompt_output_mode()
    t = Timer()

    banner("Crawling")
    pages, forms_map = crawl(target)
    good(f"Crawl complete. {len(pages)} pages, {sum(len(v) for v in forms_map.values())} forms.")

    banner("Security Headers Audit")
    hdr_present, hdr_missing = headers_check(target)
    info(f"Headers present: {list(hdr_present.keys())}")
    if hdr_missing:
        warn(f"Missing headers: {hdr_missing}")
    else:
        good("All recommended headers present (or endpoint didn't respond with headers).")

    banner("Testing for SQL Injection")
    findings = []
    for p in pages:
        findings += sqli_params(p)
        forms = forms_map.get(p, [])
        findings += sqli_forms(p, forms)
    good(f"SQLi checks complete. Findings so far: {len(findings)}")

    banner("Testing for Reflected XSS")
    for p in pages:
        findings += xss_params(p)
        forms = forms_map.get(p, [])
        findings += xss_forms(p, forms)
    good(f"XSS checks complete. Total findings: {len(findings)}")

    duration = t.stop()

    if mode in ("1","3"):
        banner("Results (Console)")
        if not findings:
            print("No issues detected by automated checks.")
        else:
            for v in findings:
                print(f"- {v['type'].upper()} via {v['vector']} at {v['url']} (evidence: {v['evidence']})")
        if hdr_missing:
            print(f"\nMissing security headers: {', '.join(hdr_missing)}")

    report_path = None
    if mode in ("2","3"):
        report_path = write_report(target, pages, findings, hdr_present, hdr_missing, duration)
        good(f"Report saved: {report_path}")

    banner("Done")
    print(f"Duration: {duration:.1f}s • Pages: {len(pages)} • Findings: {len(findings)}")
    if report_path:
        print(f"Report: {report_path}")

if __name__ == '__main__':
    run()
