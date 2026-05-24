import ssl
import socket
from datetime import datetime

def analyze_tls(hostname):
    findings = []

    # strip protocol if present
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

    except ssl.SSLCertVerificationError:
        return {
            "error": None,
            "findings": [{
                "check": "Certificate verification",
                "status": "critical",
                "detail": "Certificate is invalid or self-signed — browser will show security warning."
            }]
        }
    except ssl.SSLError as e:
        return {"error": f"SSL error: {str(e)}", "findings": []}
    except ConnectionRefusedError:
        return {"error": "Port 443 not open — site may not support HTTPS.", "findings": []}
    except socket.timeout:
        return {"error": "TLS connection timed out.", "findings": []}
    except Exception as e:
        return {"error": f"TLS check failed: {str(e)}", "findings": []}

    # --- Protocol version check ---
    if protocol == "TLSv1.3":
        findings.append({
            "check": "TLS protocol",
            "status": "good",
            "detail": f"Using {protocol} — most secure, recommended."
        })
    elif protocol == "TLSv1.2":
        findings.append({
            "check": "TLS protocol",
            "status": "warn",
            "detail": f"Using {protocol} — acceptable but TLS 1.3 is preferred."
        })
    else:
        findings.append({
            "check": "TLS protocol",
            "status": "critical",
            "detail": f"Using {protocol} — outdated and insecure, should be disabled."
        })

    # --- Cipher suite check ---
    cipher_name = cipher[0] if cipher else "Unknown"
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
    is_weak = any(w in cipher_name for w in weak_ciphers)

    findings.append({
        "check": "Cipher suite",
        "status": "critical" if is_weak else "good",
        "detail": f"{cipher_name} — {'weak cipher, vulnerable to attacks' if is_weak else 'strong cipher.'}"
    })

    # --- Certificate expiry check ---
    try:
        expire_str = cert["notAfter"]
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.utcnow()).days

        if days_left < 0:
            findings.append({
                "check": "Certificate expiry",
                "status": "critical",
                "detail": f"Certificate expired {abs(days_left)} days ago."
            })
        elif days_left < 15:
            findings.append({
                "check": "Certificate expiry",
                "status": "critical",
                "detail": f"Certificate expires in {days_left} days — renew immediately."
            })
        elif days_left < 30:
            findings.append({
                "check": "Certificate expiry",
                "status": "warn",
                "detail": f"Certificate expires in {days_left} days — renew soon."
            })
        else:
            findings.append({
                "check": "Certificate expiry",
                "status": "good",
                "detail": f"Certificate valid for {days_left} more days."
            })
    except Exception:
        findings.append({
            "check": "Certificate expiry",
            "status": "warn",
            "detail": "Could not parse certificate expiry date."
        })

    # --- Self-signed check ---
    try:
        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])

        if issuer.get("organizationName") == subject.get("organizationName"):
            findings.append({
                "check": "Certificate authority",
                "status": "warn",
                "detail": f"Possibly self-signed — issuer and subject org match: {issuer.get('organizationName')}."
            })
        else:
            findings.append({
                "check": "Certificate authority",
                "status": "good",
                "detail": f"Issued by {issuer.get('organizationName', 'Unknown CA')}."
            })
    except Exception:
        pass

    # --- Hostname match check ---
    try:
        ssl.match_hostname(cert, hostname)
        findings.append({
            "check": "Hostname match",
            "status": "good",
            "detail": f"Certificate hostname matches {hostname}."
        })
    except ssl.CertificateError:
        findings.append({
            "check": "Hostname match",
            "status": "critical",
            "detail": f"Certificate hostname does NOT match {hostname} — possible MITM risk."
        })

    return {
        "error": None,
        "hostname": hostname,
        "protocol": protocol,
        "cipher": cipher_name,
        "findings": findings
    }
