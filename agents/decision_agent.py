def decide(url_result: dict, domain_result: dict, intel_result: dict) -> dict:
    """Decision Agent: combines all agent scores into a final verdict."""
    if intel_result["listed"]:
        score = 100
    else:
        score = round(
            0.55 * url_result["risk_score"]
            + 0.30 * domain_result["risk_score"]
            + 0.15 * intel_result["risk_score"]
        )

    if score >= 70:
        verdict, action = "PHISHING", "BLOCK: block the link and alert the user"
    elif score >= 40:
        verdict, action = "SUSPICIOUS", "WARN: warn the user, do not click"
    else:
        verdict, action = "SAFE", "ALLOW: the link is safe to open"

    reasons = (
        intel_result["reasons"] + url_result["reasons"] + domain_result["reasons"]
    )

    return {
        "final_score": score,
        "verdict": verdict,
        "action": action,
        "reasons": reasons,
    }