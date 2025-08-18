### payload_alchemist/modules/brute.py

import requests
from concurrent.futures import ThreadPoolExecutor

SUBDOMAIN_WORDLIST = ["www", "mail", "admin", "webmail", "cpanel", "dev", "test", "staging"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Linux; Android 10)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.68.0"
]

def brute_subdomains(domain):
    findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for word in SUBDOMAIN_WORDLIST:
            url = f"http://{word}.{domain}"
            futures.append(executor.submit(test_url, url))
        for f in futures:
            result = f.result()
            if result:
                findings.append(result)
    return findings

def test_url(url):
    try:
        r = requests.get(url, timeout=3)
        if r.status_code < 500:
            return {"type": "subdomain_found", "url": url, "status": r.status_code}
    except:
        return None

def test_user_agents(url):
    findings = []
    for agent in USER_AGENTS:
        try:
            headers = {"User-Agent": agent}
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code < 500:
                findings.append({
                    "type": "user_agent_accessible",
                    "url": url,
                    "agent": agent,
                    "status": r.status_code
                })
        except:
            continue
    return findings
