from urllib.parse import urlparse
import re

def preprocess_url(url):

    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    pattern = re.compile(r'^(http|https)://([a-zA-Z0-9.-]+)')

    if not pattern.match(url):
        print("Invalid URL format")
        return None

    parsed_url = urlparse(url)

    processed_data = {
        "protocol": parsed_url.scheme,
        "domain": parsed_url.netloc,
        "path": parsed_url.path,
        "query": parsed_url.query
    }

    return processed_data