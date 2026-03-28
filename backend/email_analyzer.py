import re

SUSPICIOUS_EMAIL_WORDS = [
    "support", "helpdesk", "noreply", "alert", "verify",
    "secure", "update", "confirm", "account", "suspend",
    "urgent", "kyc", "refund", "prize", "winner",
    "claim", "reward", "free", "offer", "lucky"
]

SUSPICIOUS_SUBJECT_WORDS = [
    "urgent", "verify", "suspended", "blocked", "confirm",
    "winner", "prize", "claim", "refund", "kyc",
    "action required", "immediate", "alert", "warning"
]

KNOWN_LEGIT_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com", "rediffmail.com"
]


def parse_email(email_string):
    params = {"to": "", "subject": "", "body": ""}

    if email_string.startswith("mailto:"):
        content = email_string[7:]
    else:
        content = email_string

    if "?" in content:
        to, _, query = content.partition("?")
        params["to"] = to
        for part in query.split("&"):
            if "=" in part:
                key, _, value = part.partition("=")
                params[key.lower()] = value
    else:
        params["to"] = content

    return params


def analyze_email(email_string):
    result = {
        "to": None,
        "subject": None,
        "body": None,
        "prediction": "Safe Email QR",
        "risk_level": "Safe",
        "flags": []
    }

    params = parse_email(email_string)
    to = params.get("to", "")
    subject = params.get("subject", "")
    body = params.get("body", "")

    result["to"] = to if to else None
    result["subject"] = subject if subject else None
    result["body"] = body[:100] if body else None

    flags = []

    # Check 1: Valid email format
    if to and not re.match(r'^[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}$', to):
        flags.append("Invalid email address format")

    # Check 2: Suspicious words in email address
    if to:
        to_lower = to.lower()
        found = [w for w in SUSPICIOUS_EMAIL_WORDS if w in to_lower]
        if found:
            flags.append(f"Suspicious keyword in email address: {', '.join(found)}")

        # Check 3: Unknown domain
        domain = to.split("@")[-1].lower() if "@" in to else ""
        if domain and domain not in KNOWN_LEGIT_DOMAINS:
            flags.append(f"Unrecognized email domain: {domain}")

    # Check 4: Suspicious subject
    if subject:
        subj_lower = subject.lower()
        found_s = [w for w in SUSPICIOUS_SUBJECT_WORDS if w in subj_lower]
        if found_s:
            flags.append(f"Suspicious subject line: {', '.join(found_s)}")

    # Check 5: Suspicious body
    if body:
        body_lower = body.lower()
        found_b = [w for w in SUSPICIOUS_EMAIL_WORDS if w in body_lower]
        if found_b:
            flags.append(f"Suspicious content in email body: {', '.join(found_b)}")

    # Check 6: Pre-filled body (phishing tactic)
    if body and len(body) > 20:
        flags.append("Email body is pre-filled — verify before sending")

    # Determine risk
    critical = [f for f in flags if any(k in f.lower() for k in
                ["suspicious keyword", "suspicious subject", "invalid email"])]

    if len(critical) >= 2:
        result["risk_level"] = "High Risk"
        result["prediction"] = "Phishing Email QR Detected"
    elif len(critical) == 1:
        result["risk_level"] = "Medium Risk"
        result["prediction"] = "Suspicious Email QR — Verify Before Sending"
    elif flags:
        result["risk_level"] = "Low Risk"
        result["prediction"] = "Email QR has minor concerns"
    else:
        result["risk_level"] = "Safe"
        result["prediction"] = "Safe Email QR"

    result["flags"] = flags
    return result
