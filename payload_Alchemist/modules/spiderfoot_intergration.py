import subprocess
import os

def run_spiderfoot(domain):
    print(f"[*] Running SpiderFoot for passive recon on {domain}")

    output_dir = "reports"
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, f"spiderfoot_{domain}.json")
    cmd = f"spiderfoot -s {domain} -o json -m sfp_dns,sfp_whois,sfp_sslcert > {output_file}"

    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[+] SpiderFoot scan complete. Output saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"[-] SpiderFoot execution failed: {e}")
