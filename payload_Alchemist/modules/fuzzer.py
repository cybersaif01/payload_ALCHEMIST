import requests
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode

# Load payloads
def load_payloads(attack_type):
    payload_file = f"payloads/{attack_type}.json"
    if not os.path.exists(payload_file):
        print(f"[!] Payload file not found: {payload_file}")
        return []
    with open(payload_file, "r") as f:
        return json.load(f)

# Inject payloads into URLs
def inject_payloads(url, payloads):
    parsed_url = urlparse(url)
    qs = parse_qs(parsed_url.query)
    fuzzed_urls = []

    for param in qs:
        for payload in payloads:
            temp_qs = qs.copy()
            temp_qs[param] = payload
            new_query = urlencode(temp_qs, doseq=True)
            fuzzed_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            fuzzed_urls.append((fuzzed_url, payload))

    return fuzzed_urls

# Send requests and collect responses
def fuzz_urls(urls, attack_type="xss"):
    results = []
    payloads = load_payloads(attack_type)

    for url in urls:
        fuzzed = inject_payloads(url, payloads)
        for target_url, payload in fuzzed:
            try:
                res = requests.get(target_url, timeout=5)
                results.append({
                    "url": target_url,
                    "payload": payload,
                    "status_code": res.status_code,
                    "body": res.text
                })
            except Exception as e:
                results.append({
                    "url": target_url,
                    "payload": payload,
                    "status_code": 0,
                    "body": str(e)
                })

    return results
