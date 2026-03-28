import re

SUSPICIOUS_TEXT_WORDS = [
    "click here", "verify now", "act now", "urgent",
    "you have won", "congratulations", "prize", "winner",
    "claim your", "free gift", "limited time", "expires",
    "otp", "password", "pin", "cvv", "card number",
    "bank account", "aadhar", "pan card", "kyc",
    "suspended", "blocked", "immediate action"
]

PHONE_SCAM_PATTERNS = [
    r"call\s+now", r"call\s+us", r"helpline",
    r"customer\s+care", r"toll\s+free"
]


def analyze_text(text_string):
    result = {
        "prediction": "Safe Text QR",
        "risk_level": "Safe",
        "flags": [],
        "contains_url": False,
        "contains_phone": False,
        "embedded_url": None
    }

    flags = []
    text_lower = text_string.lower()

    # Check 1: Contains embedded URL
    url_match = re.search(r'https?://\S+', text_string)
    if url_match:
        result["contains_url"] = True
        result["embedded_url"] = url_match.group()
        flags.append(f"Contains embedded URL: {url_match.group()[:60]}")

    # Check 2: Contains phone number
    phone_match = re.search(r'(\+?\d[\d\s\-]{8,}\d)', text_string)
    if phone_match:
        result["contains_phone"] = True

    # Check 3: Suspicious words
    found = [w for w in SUSPICIOUS_TEXT_WORDS if w in text_lower]
    if found:
        flags.append(f"Suspicious content detected: {', '.join(found[:3])}")

    # Check 4: Phone scam patterns
    for pattern in PHONE_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            flags.append("Contains call-to-action phone scam pattern")
            break

    # Check 5: Sensitive data request
    sensitive = ["otp", "password", "pin", "cvv", "card number", "aadhar", "pan"]
    found_sensitive = [w for w in sensitive if w in text_lower]
    if found_sensitive:
        flags.append(f"Requests sensitive information: {', '.join(found_sensitive)}")

    # Check 6: Very long text (obfuscation tactic)
    if len(text_string) > 500:
        flags.append("Unusually long text content — possible obfuscation")

    # Determine risk
    critical = [f for f in flags if any(k in f.lower() for k in
                ["sensitive information", "suspicious content", "scam pattern"])]

    if len(critical) >= 1:
        result["risk_level"] = "High Risk"
        result["prediction"] = "Suspicious Text QR — Possible Scam"
    elif flags:
        result["risk_level"] = "Medium Risk"
        result["prediction"] = "Text QR has suspicious content"
    else:
        result["risk_level"] = "Safe"
        result["prediction"] = "Safe Text QR"

    result["flags"] = flags
    return result
