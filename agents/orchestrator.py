import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from url_agent import analyze_url
from domain_agent import analyze_domain
from threat_intel_agent import analyze_threat_intel
from decision_agent import decide


def scan(url: str) -> dict:
    """Orchestrator: runs the agents and makes the final decision."""
    steps = []

    intel = analyze_threat_intel(url)
    steps.append("Threat Intel Agent ran")

    url_res = analyze_url(url)
    steps.append("URL Analysis Agent ran")

    # Dynamic decision: skip slow WHOIS/SSL checks if the URL is already blocklisted
    if intel["listed"]:
        domain = {
            "agent": "Domain/WHOIS Agent",
            "risk_score": 100,
            "reasons": ["Domain check skipped because the URL is blocklisted (saved time)"],
        }
        steps.append("Domain Agent skipped (blocklist hit)")
    else:
        domain = analyze_domain(url)
        steps.append("Domain/WHOIS Agent ran")

    result = decide(url_res, domain, intel)
    result["url"] = url
    result["steps"] = steps
    return result


if __name__ == "__main__":
    urls = sys.argv[1:] or [
        "https://www.google.com",
        "http://paypal-secure-login.verify-account.xyz/signin",
        "http://192.168.1.5/bank/login.php",
    ]
    for u in urls:
        r = scan(u)
        print(f"\n{'=' * 60}\n{u}")
        print(f"VERDICT: {r['verdict']} ({r['final_score']}/100)")
        print(f"ACTION : {r['action']}")
        print("Steps  :", " -> ".join(r["steps"]))
        print("Reasons:")
        for reason in r["reasons"]:
            print("   -", reason)