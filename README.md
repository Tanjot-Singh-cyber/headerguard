# HeaderGuard
### HTTP Security Header Analyzer

HeaderGuard scans any web target and analyzes its HTTP response headers against a checklist of critical security headers. It identifies what's missing, what's misconfigured, assigns a severity, explains the attack vector, and gives the target an overall security grade.

Built with Python + Flask. Hosted on Replit.

---

## What it analyzes

| Header | Severity | What it prevents |
|---|---|---|
| Content-Security-Policy | High | XSS — blocks injection of malicious scripts |
| Strict-Transport-Security | High | MITM — forces HTTPS, prevents downgrade attacks |
| X-Frame-Options | Medium | Clickjacking — blocks iframe embedding |
| X-Content-Type-Options | Medium | MIME sniffing — stops browser from guessing content type |
| Referrer-Policy | Low | Data leakage — controls referrer info sent to third parties |
| Permissions-Policy | Low | Feature abuse — restricts camera, mic, geolocation access |

---

## Features

- **3-state header analysis** — Present, Weak, or Missing (not just pass/fail)
- **Attack explanation** — for every missing or weak header, shows what an attacker can actually do
- **Weak config detection** — flags dangerous CSP directives like `unsafe-inline` and `unsafe-eval`, short HSTS `max-age`, and deprecated `X-Frame-Options: ALLOW-FROM`
- **Info leakage detection** — flags exposed `Server`, `X-Powered-By`, and `X-AspNet-Version` headers that reveal your tech stack
- **Redirect tracking** — detects HTTP → HTTPS redirects
- **Response time measurement** — shows server response latency in ms
- **Security grade** — A+ to F based on weighted scoring
- **Risk level** — Critical / High / Medium / Low based on what's missing

---

## Bug Bounty Recon Use Case

HeaderGuard is useful as a **first recon step** before hunting on platforms like HackerOne or Bugbase.

Missing headers are rarely accepted as standalone findings, but they reveal attack surface:

- **CSP missing** → XSS payloads won't be blocked → hunt for injection points
- **HSTS missing** → check if HTTP version of the site exposes sensitive endpoints
- **X-Frame-Options missing** → look for clickjacking on sensitive actions like payments or account settings
- **Info leakage** → exposed server version → research known CVEs for that version

Use the scan results to decide where to dig deeper, not as the finding itself.

---

## Tech Stack

- Python 3
- Flask
- Requests
- HTML / CSS / JavaScript (vanilla)

---

## Project Structure

```
headerguard/
├── main.py             # Flask app — routes
├── analyzer.py         # Core analysis logic
├── requirements.txt    # Dependencies
├── templates/
│   └── index.html      # Frontend UI
└── static/
    └── style.css
```

---

## Run Locally

```bash
git clone https://github.com/Tanjot-Singh-cyber/headerguard.git
cd headerguard
pip install -r requirements.txt
python main.py
```

Then open `http://localhost:5000` in your browser.

---

## Sample Results

Tested against real targets:

| Target | Grade | Notes |
|---|---|---|
| google.com | F | Missing CSP, HSTS, and more — intentional for a marketing page |
| hackerone.com | C | Better than average but still missing key headers |
| portswigger.net | D | Makers of Burp Suite — still missing critical headers |
| bugbase.in | D | Indian bug bounty platform |

---

## Author

Tanjot Singh — B.Tech CSE, MIET Jammu  
[GitHub](https://github.com/Tanjot-Singh-cyber)
