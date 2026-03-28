import re

def extract_features(url):

    features = {}

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["has_https"] = 1 if "https" in url else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["has_hyphen"] = 1 if "-" in url else 0
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_subdomains"] = url.count(".")
    features["num_slashes"] = url.count("/")
    features["num_question"] = url.count("?")
    features["num_equal"] = url.count("=")

    features["suspicious_words"] = 1 if re.search(
        r"login|verify|secure|account|update|bank|confirm",
        url.lower()
    ) else 0

    return features