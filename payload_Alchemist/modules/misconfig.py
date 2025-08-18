import requests
import re

def clean_url(raw_url):
    return re.sub(r"\s+\[.*?\]", "", raw_url).strip()

def check_misconfig(url):
    results = []
    url = clean_url(url)

    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "PayloadAlchemist/1.0"}, allow_redirects=True)
        headers = res.headers

        # Security headers
        security_headers = {
            "Content-Security-Policy": "Missing CSP header",
            "Strict-Transport-Security": "Missing HSTS",
            "X-Frame-Options": "Missing XFO",
            "X-XSS-Protection": "Missing XXP",
            "X-Content-Type-Options": "Missing XCTO"
        }

        for header, warning in security_headers.items():
            if header not in headers:
                results.append({
                    "url": url,
                    "type": "missing_header",
                    "header": header,
                    "warning": warning
                })

    except requests.exceptions.SSLError:
        results.append({
            "url": url,
            "type": "ssl_error",
            "error": "SSL misconfiguration or invalid certificate"
        })

    except Exception as e:
        results.append({
            "url": url,
            "type": "error",
            "error": f"Failed to parse: {url} | {str(e)}"
        })

    return results

import requests

def test_clickjacking(url):
    html = f'''
    <html>
        <body>
            <h1>Clickjacking test for {url}</h1>
            <iframe src="{url}" width="800" height="600"></iframe>
        </body>
    </html>
    '''
    safe_name = url.replace('https://', '').replace('/', '_')
    file_path = f"reports/clickjack_{safe_name}.html"
    try:
        with open(file_path, 'w') as f:
            f.write(html)
        return {"url": url, "type": "clickjacking", "file": file_path}
    except Exception as e:
        return {"url": url, "type": "clickjacking", "error": str(e)}

def test_xss_no_csp(url):
    try:
        payload = "<script>alert('xss')</script>"
        test_url = f"{url}?test={payload}"
        res = requests.get(test_url, timeout=5)
        if payload in res.text:
            return {"url": test_url, "type": "xss_no_csp", "status": "reflected"}
    except Exception as e:
        return {"url": url, "type": "xss_no_csp", "error": str(e)}

def test_http_downgrade(url):
    http_url = url.replace("https://", "http://")
    try:
        res = requests.get(http_url, timeout=5, allow_redirects=False)
        if res.status_code < 300:
            return {"url": http_url, "type": "http_downgrade", "status": "accessible"}
    except Exception as e:
        return {"url": http_url, "type": "http_downgrade", "error": str(e)}

def test_mime_sniffing(url):
    try:
        res = requests.get(url, timeout=5)
        if "<script>" in res.text and "X-Content-Type-Options" not in res.headers:
            return {"url": url, "type": "mime_sniffing", "result": "possible"}
    except Exception as e:
        return {"url": url, "type": "mime_sniffing", "error": str(e)}
