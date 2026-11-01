from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
BLOCKLIST_PATH = BASE_DIR / "data" / "blocklist.txt"


def _hostname(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def load_blocklist() -> set:
    if not BLOCKLIST_PATH.exists():
        return set()
    lines = BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
    return {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}


def analyze_threat_intel(url: str) -> dict:
    """Threat Intel Agent main function (offline blocklist)."""
    host = _hostname(url)
    blocklist = load_blocklist()
    reasons = []
    score = 0

    if host in blocklist or any(host.endswith("." + b) for b in blocklist):
        reasons.append(f"'{host}' is in the known phishing blocklist")
        score = 100
    else:
        reasons.append("Not found in blocklist (this does not mean it is safe)")

    return {
        "agent": "Threat Intel Agent",
        "host": host,
        "risk_score": score,
        "listed": score == 100,
        "reasons": reasons,
    }


if __name__ == "__main__":
    for u in [
        "https://www.google.com",
        "http://paypal-secure-login.verify-account.xyz/signin",
        "http://secure-login-paypal.com@malicious-site.ru/login",
    ]:
        r = analyze_threat_intel(u)
        print(f"\n{u}\n  Risk: {r['risk_score']}/100")
        for reason in r["reasons"]:
            print("   -", reason)