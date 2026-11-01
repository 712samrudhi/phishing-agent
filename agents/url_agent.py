import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "urls.csv"
MODEL_PATH = BASE_DIR / "models" / "url_model.pkl"

# works offline (does not download the suffix list)
_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "suspend", "webscr", "claim", "gift", "free",
    "alert", "billing", "refund", "support",
]
RISKY_TLDS = {"xyz", "top", "tk", "cc", "club", "online", "info", "ru", "ml", "ga", "cf"}

FEATURE_NAMES = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_digits",
    "has_at", "has_ip", "is_https", "num_subdomains", "suspicious_words",
    "risky_tld", "has_port", "num_params", "path_length",
]


def _normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(url: str) -> dict:
    url = _normalize(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = _extract(url)
    lower = url.lower()

    return {
        "url_length": len(url),
        "domain_length": len(host),
        "num_dots": url.count("."),
        "num_hyphens": host.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_at": int("@" in url),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "is_https": int(parsed.scheme == "https"),
        "num_subdomains": len([s for s in ext.subdomain.split(".") if s]),
        "suspicious_words": sum(w in lower for w in SUSPICIOUS_WORDS),
        "risky_tld": int(ext.suffix.split(".")[-1] in RISKY_TLDS),
        "has_port": int(parsed.port is not None),
        "num_params": parsed.query.count("=") if parsed.query else 0,
        "path_length": len(parsed.path),
    }


def rule_based_reasons(f: dict) -> list:
    """Simple rules used to explain the result."""
    reasons = []
    if f["has_ip"]:
        reasons.append("Uses an IP address instead of a domain name")
    if f["has_at"]:
        reasons.append("Contains '@' symbol (often used to hide the real domain)")
    if not f["is_https"]:
        reasons.append("Site does not use HTTPS")
    if f["suspicious_words"] >= 2:
        reasons.append(f"Found {f['suspicious_words']} suspicious keywords (login, verify, secure, etc.)")
    if f["risky_tld"]:
        reasons.append("Domain ending (TLD) is commonly used in phishing")
    if f["num_subdomains"] >= 3:
        reasons.append("Too many subdomains")
    if f["num_hyphens"] >= 2:
        reasons.append("Too many hyphens in the domain")
    if f["url_length"] > 75:
        reasons.append("URL is very long")
    if f["has_port"]:
        reasons.append("Uses a non-standard port")
    return reasons


def rule_based_score(f: dict) -> int:
    score = 0
    score += 35 if f["has_ip"] else 0
    score += 30 if f["has_at"] else 0
    score += 10 if not f["is_https"] else 0
    score += min(f["suspicious_words"] * 8, 24)
    score += 15 if f["risky_tld"] else 0
    score += 10 if f["num_subdomains"] >= 3 else 0
    score += 8 if f["num_hyphens"] >= 2 else 0
    score += 5 if f["url_length"] > 75 else 0
    score += 5 if f["has_port"] else 0
    return min(score, 100)


def train_model():
    df = pd.read_csv(DATA_PATH)
    X = pd.DataFrame([extract_features(u) for u in df["url"]])[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    print("Test results:")
    print(classification_report(y_test, model.predict(X_test), zero_division=0))

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved: {MODEL_PATH}")


def analyze_url(url: str) -> dict:
    """URL Analysis Agent main function."""
    f = extract_features(url)
    reasons = rule_based_reasons(f)
    rule_score = rule_based_score(f)

    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        ml_prob = model.predict_proba(pd.DataFrame([f])[FEATURE_NAMES])[0][1]
        ml_score = round(ml_prob * 100)
        score = round(0.6 * ml_score + 0.4 * rule_score)
    else:
        ml_score = None
        score = rule_score

    return {
        "agent": "URL Analysis Agent",
        "url": url,
        "risk_score": score,
        "ml_score": ml_score,
        "rule_score": rule_score,
        "reasons": reasons,
        "features": f,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "train":
        train_model()
    else:
        test_urls = [
            "https://www.google.com",
            "http://paypal-secure-login.verify-account.xyz/signin",
            "http://192.168.1.5/bank/login.php",
        ]
        for u in test_urls:
            r = analyze_url(u)
            print(f"\n{u}\n  Risk: {r['risk_score']}/100 (ML={r['ml_score']}, Rules={r['rule_score']})")
            for reason in r["reasons"]:
                print("   -", reason)