import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois


def _hostname(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).hostname or ""


def get_domain_age_days(host: str):
    try:
        w = whois.whois(host)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


def check_ssl(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        return {"valid": True, "days_left": days_left}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "days_left": None, "error": "invalid certificate"}
    except Exception:
        return {"valid": None, "days_left": None, "error": "no HTTPS / unreachable"}


def analyze_domain(url: str) -> dict:
    """Domain/WHOIS Agent main function."""
    host = _hostname(url)
    reasons = []
    score = 0

    age = get_domain_age_days(host)
    if age is None:
        reasons.append("WHOIS registration data not found")
        score += 20
    elif age < 30:
        reasons.append(f"Domain is very new ({age} days old)")
        score += 60
    elif age < 180:
        reasons.append(f"Domain is fairly new ({age} days old)")
        score += 30
    else:
        reasons.append(f"Domain is old ({age // 365} years)")

    ssl_info = check_ssl(host)
    if ssl_info["valid"] is False:
        reasons.append("SSL certificate is invalid")
        score += 30
    elif ssl_info["valid"] is None:
        reasons.append("HTTPS not available or site unreachable")
        score += 15
    else:
        reasons.append(f"SSL is valid ({ssl_info['days_left']} days left)")

    return {
        "agent": "Domain/WHOIS Agent",
        "host": host,
        "risk_score": min(score, 100),
        "domain_age_days": age,
        "ssl": ssl_info,
        "reasons": reasons,
    }


if __name__ == "__main__":
    for u in ["https://www.google.com", "http://paypal-secure-login.verify-account.xyz/signin"]:
        r = analyze_domain(u)
        print(f"\n{u}\n  Risk: {r['risk_score']}/100")
        for reason in r["reasons"]:
            print("   -", reason)