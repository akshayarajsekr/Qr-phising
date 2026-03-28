import re

# Known legitimate UPI handles
LEGITIMATE_HANDLES = [
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    "ybl", "ibl", "axl", "paytm", "apl",
    "upi", "gpay", "phonepe", "amazonpay",
    "indus", "kotak", "rbl", "hsbc", "pnb",
    "boi", "cnrb", "ucobank", "allbank"
]

# Suspicious words in UPI IDs or payee names
SUSPICIOUS_WORDS = [
    "support", "helpdesk", "refund", "cashback", "reward",
    "prize", "winner", "lucky", "bonus", "free",
    "verify", "kyc", "update", "block", "suspend",
    "alert", "urgent", "immediate", "claim", "offer",
    "discount", "lottery", "gift", "help", "care",
    "service", "customer", "official", "secure", "safe"
]

# Known scam payee name patterns
SCAM_PATTERNS = [
    r"paytm.?support", r"google.?pay.?help", r"phonepe.?care",
    r"amazon.?refund", r"bank.?helpline", r"kyc.?update",
    r"refund.?process", r"prize.?claim", r"reward.?redeem",
    r"sbi.?support", r"hdfc.?help", r"icici.?care"
]


def parse_upi(upi_string):
    params = {}
    upi_string = upi_string.strip()

    if upi_string.startswith("upi://pay?"):
        query = upi_string[len("upi://pay?"):]
    elif upi_string.startswith("upi://"):
        query = upi_string[len("upi://"):]
    else:
        query = upi_string

    for part in query.split("&"):
        if "=" in part:
            key, _, value = part.partition("=")
            params[key.lower()] = value

    return params


def analyze_upi(upi_string):
    result = {
        "upi_id": None,
        "payee_name": None,
        "amount": None,
        "remarks": None,
        "risk_level": "Safe",
        "prediction": "Safe Payment QR",
        "flags": []
    }

    params = parse_upi(upi_string)

    upi_id = params.get("pa", "")
    payee_name = params.get("pn", "")
    amount = params.get("am", "")
    remarks = params.get("tn", "")

    result["upi_id"] = upi_id
    result["payee_name"] = payee_name
    result["amount"] = amount if amount else None
    result["remarks"] = remarks if remarks else None

    flags = []

    # ── Check 1: Valid UPI ID format ──
    if upi_id:
        if not re.match(r'^[\w.\-]+@[\w]+$', upi_id):
            flags.append("Invalid UPI ID format")

        # ── Check 2: Unknown or suspicious handle ──
        handle = upi_id.split("@")[-1].lower() if "@" in upi_id else ""
        if handle and not any(h in handle for h in LEGITIMATE_HANDLES):
            flags.append(f"Unrecognized UPI handle: @{handle}")

        # ── Check 3: Suspicious words in UPI ID ──
        upi_lower = upi_id.lower()
        found = [w for w in SUSPICIOUS_WORDS if w in upi_lower]
        if found:
            flags.append(f"Suspicious keyword in UPI ID: {', '.join(found)}")

        # ── Check 4: Random character pattern (scam IDs often look random) ──
        local = upi_id.split("@")[0]
        digit_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
        if digit_ratio > 0.6 and len(local) > 8:
            flags.append("UPI ID appears randomly generated")

    else:
        flags.append("No UPI ID found in QR code")

    # ── Check 5: Suspicious payee name ──
    if payee_name:
        name_lower = payee_name.lower()
        found_words = [w for w in SUSPICIOUS_WORDS if w in name_lower]
        if found_words:
            flags.append(f"Suspicious keyword in payee name: {', '.join(found_words)}")

        for pattern in SCAM_PATTERNS:
            if re.search(pattern, name_lower):
                flags.append(f"Payee name matches known scam pattern")
                break

    # ── Check 6: Pre-filled amount (pressure tactic) ──
    if amount:
        try:
            amt = float(amount)
            if amt > 10000:
                flags.append(f"Large pre-filled amount: Rs.{amt}")
            elif amt > 0:
                flags.append(f"Pre-filled amount: Rs.{amt} — verify before paying")
        except ValueError:
            flags.append("Invalid amount format in QR")

    # ── Check 7: Suspicious remarks ──
    if remarks:
        remarks_lower = remarks.lower()
        found_r = [w for w in SUSPICIOUS_WORDS if w in remarks_lower]
        if found_r:
            flags.append(f"Suspicious keyword in remarks: {', '.join(found_r)}")

    # ── Determine risk level ──
    critical_flags = [f for f in flags if any(k in f.lower() for k in [
        "invalid", "suspicious keyword", "scam pattern", "randomly generated", "large pre-filled"
    ])]

    if len(critical_flags) >= 2:
        result["risk_level"] = "High Risk"
        result["prediction"] = "Fraudulent Payment QR Detected"
    elif len(critical_flags) == 1:
        result["risk_level"] = "Medium Risk"
        result["prediction"] = "Suspicious Payment QR - Verify Before Paying"
    elif flags:
        result["risk_level"] = "Low Risk"
        result["prediction"] = "Payment QR has minor concerns"
    else:
        result["risk_level"] = "Safe"
        result["prediction"] = "Safe Payment QR"

    result["flags"] = flags
    return result
