
import subprocess


def find_subdomains(domain):
    print(f"[Recon] Running subfinder on {domain}")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=True
        )
        return list(set(result.stdout.strip().split("\n")))
    except Exception as e:
        print(f"[Error] subfinder failed: {e}")
        return []



def check_live_subdomains(subdomains, status_codes=False):
    print("[Recon] Checking liveness with httpx")
    live = []
    
    # Save subdomains to temp file
    with open("temp_subs.txt", "w") as f:
        for sub in subdomains:
            f.write(sub + "\n")

    try:
        if status_codes:
            result = subprocess.run(["httpx", "-sc", "-l", "temp_subs.txt"], capture_output=True, text=True)
        else:
            result = subprocess.run(["httpx", "-l", "temp_subs.txt"], capture_output=True, text=True)
        
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                live.append(line.strip())

    except Exception as e:
        print(f"[Error] httpx failed: {e}")

    return live


def get_historical_urls(domain):
    print(f"[Recon] Pulling historical URLs with gau")
    try:
        result = subprocess.run(
            ["gau", domain],
            capture_output=True, text=True, check=True
        )
        urls = result.stdout.strip().split("\n")
        return [url for url in urls if "?" in url]
    except Exception as e:
        print(f"[Error] gau failed: {e}")
        return []
