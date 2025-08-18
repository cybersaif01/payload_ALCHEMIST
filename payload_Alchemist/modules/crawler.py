### payload_alchemist/modules/crawler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (PayloadAlchemist)"
}

def get_html(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=5)
        return res.text
    except:
        return ""

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag['href']
        full = urljoin(base_url, href)
        if urlparse(full).netloc in base_url:
            links.add(full)
    return links

def extract_js_endpoints(html):
    js_patterns = [
        r"fetch\(['\"](.*?)['\"]",
        r"XMLHttpRequest\(['\"](.*?)['\"]",
        r"\$.ajax\({.*?url: ['\"](.*?)['\"]",
        r"location\.href\s*=\s*['\"](.*?)['\"]",
        r"window\.location\s*=\s*['\"](.*?)['\"]"
    ]
    found = set()
    for pattern in js_patterns:
        try:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                if not m.startswith("http") and not m.startswith("#"):
                    found.add(m)
        except re.error as e:
            print(f"[Regex Error] Pattern '{pattern}' failed: {e}")
    return found

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        full_action = urljoin(base_url, action) if action else base_url
        forms.append({
            "url": full_action,
            "method": method,
            "inputs": inputs
        })
    return forms

def crawl_site(url):
    html = get_html(url)
    links = extract_links(html, url)
    js_endpoints = extract_js_endpoints(html)
    forms = extract_forms(html, url)
    return {
        "links": list(links),
        "js_endpoints": list(js_endpoints),
        "forms": forms
    }
