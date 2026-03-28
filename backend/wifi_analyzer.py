import re

SUSPICIOUS_SSID_WORDS = [
    "free", "public", "open", "guest", "hack", "spy",
    "bank", "secure", "official", "government", "police",
    "airport", "hotel", "starbucks", "mcdonalds"
]

KNOWN_EVIL_TWIN_PATTERNS = [
    r"free.?wifi", r"public.?wifi", r"open.?network",
    r"airport.?wifi", r"hotel.?wifi", r"secure.?net"
]


def parse_wifi(wifi_string):
    params = {}
    content = wifi_string
    if content.startswith("WIFI:"):
        content = content[5:]
    if content.endswith(";;"):
        content = content[:-2]

    for part in re.findall(r'([A-Z]+):([^;]*);', content):
        params[part[0].upper()] = part[1]

    return params


def analyze_wifi(wifi_string):
    result = {
        "ssid": None,
        "security": None,
        "hidden": False,
        "prediction": "Safe WiFi QR",
        "risk_level": "Safe",
        "flags": []
    }

    params = parse_wifi(wifi_string)

    ssid = params.get("S", "")
    security = params.get("T", "nopass").upper()
    hidden = params.get("H", "false").lower() == "true"

    result["ssid"] = ssid if ssid else "Unknown"
    result["security"] = security if security else "None"
    result["hidden"] = hidden

    flags = []

    # Check 1: No password / open network
    if security in ["NOPASS", "NONE", ""]:
        flags.append("Open network — no password protection")

    # Check 2: Weak security
    elif security == "WEP":
        flags.append("Weak security protocol (WEP) — easily hackable")

    # Check 3: Hidden network
    if hidden:
        flags.append("Hidden network — could be an evil twin attack")

    # Check 4: Suspicious SSID
    if ssid:
        ssid_lower = ssid.lower()
        found = [w for w in SUSPICIOUS_SSID_WORDS if w in ssid_lower]
        if found:
            flags.append(f"Suspicious network name keyword: {', '.join(found)}")

        for pattern in KNOWN_EVIL_TWIN_PATTERNS:
            if re.search(pattern, ssid_lower):
                flags.append("Network name matches known evil twin pattern")
                break

    # Check 5: No SSID
    if not ssid:
        flags.append("No network name found in QR code")

    # Determine risk
    critical = [f for f in flags if any(k in f.lower() for k in
                ["evil twin", "weak security", "suspicious network"])]

    if len(critical) >= 1 or len(flags) >= 3:
        result["risk_level"] = "High Risk"
        result["prediction"] = "Suspicious WiFi QR — Do Not Connect"
    elif flags:
        result["risk_level"] = "Medium Risk"
        result["prediction"] = "WiFi QR has security concerns"
    else:
        result["risk_level"] = "Safe"
        result["prediction"] = "Safe WiFi QR"

    result["flags"] = flags
    return result
