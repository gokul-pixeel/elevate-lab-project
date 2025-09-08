
# Web Application Vulnerability Scanner

Medium-complexity Python project for internship submission. Crawls a target site, tests for **SQL Injection** and **Reflected XSS**, audits **security headers**, and outputs results to console and/or an **HTML report** (default).

## Safe Demo Targets (permissioned/lab only)
- http://testphp.vulnweb.com/
- https://demo.testfire.net/
- https://juice-shop.herokuapp.com/ (may require local setup)

> **Legal**: Scan only systems you own or have explicit permission to test.

## Setup
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python scanner.py
```
