import requests
from bs4 import BeautifulSoup
import re

def clean_url(raw_url):
    # Remove ANSI escape codes and brackets like " [200]"
    return re.sub(r"\s+\[.*?\]", "", raw_url).strip()

def fingerprint_site(url):
    results = []
    url = clean_url(url)

    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "PayloadAlchemist/1.0"})
        status = res.status_code
        content_type = res.headers.get("Content-Type", "")

        # Record headers
        results.append({
            "type": "headers",
            "url": url,
            "server": res.headers.get("Server", "unknown"),
            "x-powered-by": res.headers.get("X-Powered-By", "unknown"),
            "status": status
        })

        # Redirects
        if status in [301, 302, 303]:
            results.append({
                "url": url,
                "type": "redirect_notice",
                "location": res.headers.get("Location", "unknown"),
                "status": status
            })
            return results

        # Errors
        if status >= 400:
            results.append({
                "url": url,
                "type": "fingerprint_error",
                "error": f"HTTP {status}: Unreachable or restricted"
            })
            return results

        if "html" not in content_type:
            results.append({
                "url": url,
                "type": "fingerprint_error",
                "error": f"Non-HTML content: {content_type}"
            })
            return results

        # Parse HTML
        soup = BeautifulSoup(res.text, "html.parser")

        # CMS Detection
        cms = None
        if "wp-content" in res.text:
            cms = "WordPress"
        elif "drupal" in res.text:
            cms = "Drupal"
        elif "joomla" in res.text.lower():
            cms = "Joomla"
        elif soup.find("meta", {"name": "generator"}):
            cms = soup.find("meta", {"name": "generator"}).get("content", "Unknown")

        title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"

        results.append({
            "url": url,
            "type": "fingerprint_info",
            "status": status,
            "title": title,
            "cms": cms or "Unknown"
        })

    except Exception as e:
        results.append({
            "url": url,
            "type": "fingerprint_error",
            "error": f"Failed to parse: {url} | {str(e)}"
        })

    return results
