import whois
from datetime import datetime, timezone


def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None, None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        if age_days < 30:
            risk = "High Risk"
        elif age_days < 180:
            risk = "Medium Risk"
        else:
            risk = "Safe"

        return age_days, risk

    except Exception:
        return None, None
