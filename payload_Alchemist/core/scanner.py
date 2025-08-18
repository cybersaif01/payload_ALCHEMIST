### payload_alchemist/core/scanner.py

import requests
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def load_payloads(attack_type):
    path = os.path.join("payloads", f"{attack_type}.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Error] Could not load payloads from {path}: {e}")
        return []

def fuzz_urls(urls, attack_type="xss"):
    print(f"[Fuzzer] Testing {len(urls)} URLs with {attack_type.upper()} payloads")
    payloads = load_payloads(attack_type)
    results = []

    for url in urls:
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)

        for payload in payloads:
            tampered_params = {k: payload for k in original_params.keys()}
            new_query = urlencode(tampered_params, doseq=True)
            tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

            try:
                r = requests.get(tampered_url, timeout=5)
                results.append({
                    "url": tampered_url,
                    "payload": payload,
                    "attack_type": attack_type,
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300]
                })
            except:
                continue

    return results

def crawl_links_with_params(domains):
    print("[Scanner] Crawling pages for links and forms with query parameters")
    found_urls = set()

    for domain in domains:
        base_url = f"http://{domain}" if not domain.startswith("http") else domain
        try:
            r = requests.get(base_url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")

            # Extract <a> hrefs with query params
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.query:
                    found_urls.add(full_url)

            # Extract GET forms with input fields
            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action", base_url)
                if method == "get":
                    full_url = urljoin(base_url, action)
                    inputs = form.find_all("input")
                    if inputs:
                        params = "&".join([f"{inp.get('name')}=test" for inp in inputs if inp.get("name")])
                        if params:
                            test_url = f"{full_url}?{params}"
                            found_urls.add(test_url)
        except:
            continue

    return list(found_urls)
