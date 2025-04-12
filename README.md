# 🛡️ Web Vulnerability Scanner

A multi-threaded terminal-based web vulnerability scanner that detects common security issues such as:

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Clickjacking
- CSRF (Cross-Site Request Forgery)
- SSRF (Server-Side Request Forgery)
- IDOR (Insecure Direct Object Reference)
- LFI (Local File Inclusion)
- RCE (Remote Command Execution)

It uses deep crawling and input fuzzing techniques to scan web applications efficiently.

---

## 🚀 Features

- ✅ Deep link crawling (up to configurable depth)
- ✅ Multi-threaded scanning with live progress bars
- ✅ Payload fuzzing on input forms and URL parameters
- ✅ Thread-level scan logging
- ✅ No setup server needed — fully CLI-based

---

## 📦 Requirements

Install the required packages using pip:

```bash
pip install requests beautifulsoup4 tqdm
🧠 How It Works
Accepts a target URL.

Recursively crawls internal links (up to depth = 2).

Scans each discovered page with multiple vulnerability checks.

Displays progress per vulnerability and a summary of results.

🛠️ Usage
bash
Copy
Edit
python scanner.py
You'll be prompted to enter a target URL like:

bash
Copy
Edit
Enter target URL (http:// or https://): https://example.com
📄 Example Output
bash
Copy
Edit
=== Web Scanner CLI ===
Enter target URL (http:// or https://): https://testsite.com
Discovered 12 URLs for scanning.

Scanning started...

[✓] SQL Injection on https://testsite.com/login
[✓] XSS on https://testsite.com/comments
[✓] Clickjacking on https://testsite.com
...

=== Scan Results ===
[SQLi] Vulnerability on https://testsite.com/login with payload: ' OR '1'='1
[XSS] Vulnerability on https://testsite.com/comments with payload: <script>alert('XSS')</script>
...
📚 Payload Sources
XSS: Common script-based payloads

SQLi: Union-based and boolean-based injections

CSRF: Missing token detection

SSRF: Internal network access probes

LFI: File traversal strings

RCE: Command injection attempts

⚠️ Disclaimer
This tool is intended only for educational purposes and authorized penetration testing. Do not use it on systems you do not own or have explicit permission to test.

🤝 Contributing
Pull requests are welcome! If you’d like to suggest features or fixes, please open an issue first.
