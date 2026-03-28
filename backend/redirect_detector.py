import requests

def check_redirect(url):

    try:

        response = requests.get(url, allow_redirects=True, timeout=5)

        final_url = response.url
        redirects = len(response.history)

        return final_url, redirects

    except:

        return url, 0