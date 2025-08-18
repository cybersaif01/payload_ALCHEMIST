import sys
import socket
import re
import os
import subprocess
import functools
from datetime import datetime

# ===== Import your scanner modules here =====
from core.recon import find_subdomains, check_live_subdomains
from core.scanner import crawl_links_with_params
from modules.fuzzer import fuzz_urls
from core.detector import analyze_response
from modules.spiderfoot_intergration import run_spiderfoot
from modules.fingerprint import fingerprint_site
from modules.misconfig import (
    test_clickjacking,
    check_misconfig,
    test_xss_no_csp,
    test_http_downgrade,
    test_mime_sniffing
)
from modules.vuln_checks import check_open_redirects, check_directory_listing
from core.exploit import exploit_open_redirect

# ===== Flask API =====
from flask import Flask, request, jsonify
from io import StringIO
app = Flask(__name__, static_folder='node_server/public')

# Force immediate output flushing
sys.stdout = sys.stderr = open(sys.stdout.fileno(), 'w', buffering=1)
print = functools.partial(print, flush=True)

def run_nmap(ip, ports="1-1024"):
    try:
        port_str = ",".join(str(p) for p in ports) if isinstance(ports, list) else ports
        result = subprocess.run(
            ["nmap", "-Pn", "-p", port_str, "--open", ip],
            capture_output=True, text=True, check=True, stderr=subprocess.DEVNULL,
        )
        open_ports = re.findall(r"^(\d+)/tcp\s+open", result.stdout, re.MULTILINE)
        return {"ip": ip, "open_ports": list(map(int, open_ports))}
    except subprocess.CalledProcessError as e:
        return {"ip": ip, "error": f"Nmap scan failed with exit code {e.returncode}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def run_nmap_detailed(ip, ports="1-100"):
    try:
        result = subprocess.run(
            ["nmap", "-sT", "-sV", "-Pn", "-T4", "-p", ports, ip],
            capture_output=True, text=True, check=True, stderr=subprocess.DEVNULL
        )
        return result.stdout
    except Exception as e:
        return f"[!] Nmap error: {e}"

def print_findings(vulns, attack):
    if not vulns:
        print(f"[-] No {attack.upper()} vulnerabilities found.")
        return
    print(f"[+] {attack.upper()} vulnerabilities detected:")
    for entry in vulns:
        print(f"    - {entry['url']} | Payload: {entry['payload']} | Confidence: {entry['confidence']}")

def print_fingerprint(results):
    print("[+] Fingerprint Results:")
    for entry in results:
        if isinstance(entry, dict):
            if entry.get("type") == "redirect_notice":
                print(f"    - REDIRECT @ {entry['url']} → {entry.get('location', 'unknown')}")
            elif entry.get("type") == "fingerprint_info":
                print(f"    - {entry['url']} | Title: {entry['title']} | CMS: {entry['cms']}")
            elif entry.get("type") in ["fingerprint_error", "error"]:
                print(f"    - ERROR @ {entry['url']} => {entry['error']}")

def extract_hostname(url):
    host = url.split("://")[-1].split("/")[0]
    return re.sub(r"\s*\[\d{3}\]$", "", host)

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def run_payload_alchemist_cli(domain, mode="full", save_report=False):
    print("=" * 60)
    print(" Payload Alchemist - Automated Offensive Recon Tool (CLI)")
    print("=" * 60)
    print(f" Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    live_subs = []

    # Modes requiring subdomain discovery
    if mode in ["recon", "nmap", "full"]:
        print(f"[*] Finding subdomains for: {domain}")
        subdomains = find_subdomains(domain)
        if not subdomains:
            print("[-] No subdomains found!")
            return
        print("[+] Subdomains found:")
        for sub in subdomains:
            print(f"    - {sub}")
        print("[*] Checking live subdomains")
        live_subs = check_live_subdomains(subdomains, status_codes=True)
        if not live_subs:
            print("[-] No live subdomains found!")
            return
        print("[+] Live subdomains:")
        for sub in live_subs:
            print(f"    [+] {sub}")

    # Nmap mode or full
    if mode == "nmap" or mode == "full":
        print("[*] Running Nmap scans on live subdomains")
        for url in live_subs:
            hostname = extract_hostname(url)
            ip = resolve_ip(hostname)
            if not ip:
                print(f"[-] Could not resolve IP for {hostname}")
                continue
            quick_scan = run_nmap(ip, ports="--top-ports 100")
            if quick_scan and quick_scan.get("open_ports"):
                print(f"[+] Open ports on {hostname} ({ip}): {quick_scan['open_ports']}")
                ports_str = ",".join(str(p) for p in quick_scan["open_ports"])
                print(f"[*] Detailed Nmap scan on {ip}:\n{run_nmap_detailed(ip, ports=ports_str)}")
            else:
                err = quick_scan.get("error") if quick_scan else "No results"
                print(f"[-] No open ports found for {hostname}: {err}")

    # Recon mode or full
    if mode == "recon" or mode == "full":
        print("[*] Running SpiderFoot for OSINT")
        run_spiderfoot(domain)
        print("[*] Performing web fingerprinting")
        fingerprint_findings = []
        for url in live_subs:
            fingerprint_findings.extend(fingerprint_site(url))
        print_fingerprint(fingerprint_findings)
        print("[*] Checking for misconfigurations & headers")
        active_exploits = []
        for url in live_subs:
            misconfigs = check_misconfig(url)
            if misconfigs:
                for m in misconfigs:
                    print(f"    - {m}")
            headers = [m["header"] for m in misconfigs if m.get("type") == "missing_header"]
            if "X-Frame-Options" not in headers:
                active_exploits.append(test_clickjacking(url))
            if "Content-Security-Policy" not in headers:
                res = test_xss_no_csp(url)
                if res:
                    active_exploits.append(res)
            if "Strict-Transport-Security" not in headers:
                res = test_http_downgrade(url)
                if res:
                    active_exploits.append(res)
            if "X-Content-Type-Options" not in headers:
                res = test_mime_sniffing(url)
                if res:
                    active_exploits.append(res)
        print("[+] Active Exploit Findings:")
        for x in active_exploits:
            print(f"    - {x}")
        print("[*] Checking for extra vulnerabilities")
        for url in live_subs:
            for item in check_open_redirects(url):
                print(f"    - [OPEN REDIRECT] {item}")
            for item in check_directory_listing(url):
                print(f"    - [DIR LISTING] {item}")
        print("[*] Auto exploiting open redirects")
        open_redirect_targets = []
        for url in live_subs:
            open_redirect_targets.extend(check_open_redirects(url))
        if open_redirect_targets:
            exploit_open_redirect(open_redirect_targets)

    # Fuzz mode or full
    if mode == "fuzz" or mode == "full":
        print("[*] Crawling URLs with params")
        start_urls = live_subs if mode == "full" else [domain]
        urls_to_fuzz = crawl_links_with_params(start_urls)
        print(f"[+] Found {len(urls_to_fuzz)} URLs to fuzz")
        print("[*] Fuzzing for XSS")
        xss_results = fuzz_urls(urls_to_fuzz, attack_type="xss")
        xss_findings = analyze_response(xss_results, "xss")
        print_findings(xss_findings, "xss")
        print("[*] Fuzzing for SQLi")
        sqli_results = fuzz_urls(urls_to_fuzz, attack_type="sqli")
        sqli_findings = analyze_response(sqli_results, "sqli")
        print_findings(sqli_findings, "sqli")
        if save_report:
            print("[*] Saving Report")
            # Assuming save_report is a function you have elsewhere
            save_report({"xss": xss_findings, "sqli": sqli_findings})
            print("[+] Report saved to /reports")
        else:
            print("[*] Skipping report save")
    print("\n[+] Scan completed!")

@app.route("/api/scan", methods=["POST"])
def scan_api():
    data = request.get_json()
    domain = data.get("domain")
    mode = data.get("mode", "full")
    save_report_flag = data.get("save_report", False)

    # Capture stdout during the scan
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    try:
        run_payload_alchemist_cli(domain, mode, save_report_flag)
        output = mystdout.getvalue()
        error = ""
    except Exception as e:
        output = mystdout.getvalue()
        error = str(e)
    finally:
        sys.stdout = old_stdout
    return jsonify({"output": output, "error": error})

if __name__ == "__main__":
    # CLI mode
    if len(sys.argv) > 1 and sys.argv[1] != "runserver":
        if len(sys.argv) < 2:
            print("Usage: python main.py <domain> [mode] [--save-report]")
            print("Modes: full (default), recon, nmap, fuzz")
            sys.exit(1)
        domain = sys.argv[1]
        mode = "full"
        save_report_flag = False
        if len(sys.argv) > 2:
            mode = sys.argv[2].lower()
            if mode not in ["full", "recon", "nmap", "fuzz"]:
                print("Invalid mode. Using 'full' as default.")
                mode = "full"
        if "--save-report" in sys.argv:
            save_report_flag = True
        run_payload_alchemist_cli(domain, mode, save_report_flag)
    else:
        # Flask API mode: python main.py runserver (or just python main.py)
        app.run(debug=True)
