import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Clean function to strip status codes or brackets
def clean_url(url):
    return url.split(" ")[0].strip()

def check_open_redirects(base_url):
    results = []
    paths = [
        "/redirect?url=https://evil.com",
        "/?next=https://evil.com",
        "/login?redirect=https://evil.com",
        "/out?target=https://evil.com"
    ]

    for path in paths:
        try:
            test_url = urljoin(clean_url(base_url), path)
            res = requests.get(test_url, allow_redirects=False, timeout=5)
            loc = res.headers.get("Location", "")
            if "evil.com" in loc:
                results.append({
                    "url": test_url,
                    "type": "open_redirect",
                    "status": res.status_code,
                    "location": loc
                })
        except Exception as e:
            results.append({
                "url": base_url,
                "type": "error",
                "error": f"Open redirect scan failed: {str(e)}"
            })

    return results


def check_directory_listing(base_url):
    results = []
    test_paths = ["/", "/files/", "/backup/", "/admin/", "/logs/", "/uploads/"]

    for path in test_paths:
        try:
            test_url = urljoin(clean_url(base_url), path)
            res = requests.get(test_url, timeout=5)
            if res.status_code == 200 and "Index of" in res.text:
                soup = BeautifulSoup(res.text, "html.parser")
                links = soup.find_all("a")
                if any("Parent Directory" in link.text for link in links):
                    results.append({
                        "url": test_url,
                        "type": "directory_listing",
                        "status": res.status_code
                    })
        except Exception as e:
            results.append({
                "url": base_url,
                "type": "error",
                "error": f"Directory listing scan failed: {str(e)}"
            })

    return results
