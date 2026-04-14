# analyzer.py

import requests
import time

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Prevents XSS attacks by whitelisting allowed content sources.",
        "recommendation": "Add a strict CSP policy. e.g. default-src 'self'",
        "attack": "Without CSP, an attacker can inject malicious scripts into your page and steal session cookies or redirect users to phishing sites.",
        "weak_values": ["unsafe-inline", "unsafe-eval", "*"],
        "weak_message": "CSP contains dangerous directives — unsafe-inline or unsafe-eval allows arbitrary script execution, defeating the purpose of CSP."
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Forces HTTPS connections, preventing downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "attack": "Without HSTS, an attacker on the same network can intercept HTTP traffic and perform a man-in-the-middle attack before HTTPS kicks in.",
        "min_max_age": 15552000,  # 6 months in seconds
        "weak_message": "HSTS max-age is too short (less than 6 months) — gives attackers a window to perform downgrade attacks."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Prevents clickjacking by blocking your page from being embedded in iframes.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "attack": "Without this, an attacker can embed your page in a hidden iframe and trick users into clicking buttons they can't see — stealing clicks, form submissions, or credentials.",
        "deprecated_values": ["ALLOW-FROM"],
        "weak_message": "ALLOW-FROM is deprecated and not supported in modern browsers — your clickjacking protection may not be working."
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Stops browser from guessing content type, preventing MIME sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "attack": "Without this, an attacker can upload a file with a misleading extension and the browser may execute it as a script.",
        "weak_values": [],
        "weak_message": None
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
        "attack": "Without this, sensitive URL parameters (like tokens or user IDs) in your URL can leak to third-party sites through the Referer header.",
        "weak_values": ["unsafe-url", "no-referrer-when-downgrade"],
        "weak_message": "Referrer policy is too permissive — full URLs including sensitive parameters may leak to external sites."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Restricts access to browser features like camera, mic, and geolocation.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "attack": "Without this, malicious third-party scripts embedded in your page can silently request access to camera, microphone, or location.",
        "weak_values": [],
        "weak_message": None
    }
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def analyze_headers(url):
    # normalize URL
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        start_time = time.time()
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "HeaderGuard-Scanner/1.0"}
        )
        response_time = round((time.time() - start_time) * 1000)  # ms
    except requests.exceptions.SSLError:
        return {"error": "SSL certificate error — site may have an invalid or expired certificate."}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to the target URL. Check if the site is reachable."}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out after 10 seconds."}
    except requests.exceptions.MissingSchema:
        return {"error": "Invalid URL format."}

    headers = response.headers
    results = []
    score = 0
    total = len(SECURITY_HEADERS)

    # check redirect
    redirect_info = None
    if response.history:
        initial_url = response.history[0].url
        final_url = response.url
        if initial_url.startswith("http://") and final_url.startswith("https://"):
            redirect_info = {
                "detected": True,
                "type": "HTTP to HTTPS redirect detected — good practice.",
                "safe": True
            }
        else:
            redirect_info = {
                "detected": True,
                "type": f"Redirect detected: {initial_url} → {final_url}",
                "safe": False
            }

    # check info leakage
    info_leaks = []
    for leak_header in INFO_LEAK_HEADERS:
        if leak_header in headers:
            info_leaks.append({
                "header": leak_header,
                "value": headers[leak_header],
                "message": f"Server is exposing {leak_header}: {headers[leak_header]} — reveals technology stack to attackers."
            })

    # analyze each security header
    for header, info in SECURITY_HEADERS.items():
        present = header in headers
        status = "missing"
        warning_message = None

        if present:
            value = headers[header]
            status = "present"

            # CSP weak check
            if header == "Content-Security-Policy":
                for weak in info["weak_values"]:
                    if weak in value:
                        status = "weak"
                        warning_message = info["weak_message"]
                        break

            # HSTS max-age check
            elif header == "Strict-Transport-Security":
                try:
                    for part in value.split(";"):
                        part = part.strip()
                        if part.startswith("max-age"):
                            max_age = int(part.split("=")[1].strip())
                            if max_age < info["min_max_age"]:
                                status = "weak"
                                warning_message = info["weak_message"]
                            break
                except Exception:
                    pass

            # X-Frame-Options deprecated check
            elif header == "X-Frame-Options":
                for deprecated in info.get("deprecated_values", []):
                    if deprecated in value.upper():
                        status = "weak"
                        warning_message = info["weak_message"]
                        break

            # Referrer-Policy weak check
            elif header == "Referrer-Policy":
                for weak in info["weak_values"]:
                    if weak in value:
                        status = "weak"
                        warning_message = info["weak_message"]
                        break

            if status == "present":
                score += 1
            elif status == "weak":
                score += 0.5  # partial credit for weak headers

        results.append({
            "header": header,
            "status": status,  # present / weak / missing
            "severity": info["severity"],
            "description": info["description"],
            "recommendation": info["recommendation"] if status != "present" else None,
            "attack": info["attack"] if status != "present" else None,
            "value": headers.get(header, None),
            "warning_message": warning_message
        })

    grade = get_grade(score, total)
    risk_level = get_risk_level(results)

    return {
        "url": response.url,
        "status_code": response.status_code,
        "response_time_ms": response_time,
        "results": results,
        "score": score,
        "total": total,
        "grade": grade,
        "risk_level": risk_level,
        "redirect_info": redirect_info,
        "info_leaks": info_leaks
    }


def get_grade(score, total):
    percentage = (score / total) * 100
    if percentage == 100:
        return "A+"
    elif percentage >= 80:
        return "A"
    elif percentage >= 60:
        return "B"
    elif percentage >= 40:
        return "C"
    elif percentage >= 20:
        return "D"
    else:
        return "F"


def get_risk_level(results):
    missing_high = any(
        r["severity"] == "High" and r["status"] == "missing" for r in results
    )
    weak_high = any(
        r["severity"] == "High" and r["status"] == "weak" for r in results
    )
    missing_medium = any(
        r["severity"] == "Medium" and r["status"] == "missing" for r in results
    )

    if missing_high:
        return "Critical"
    elif weak_high or missing_medium:
        return "High"
    elif any(r["status"] in ["missing", "weak"] for r in results):
        return "Medium"
    else:
        return "Low"
