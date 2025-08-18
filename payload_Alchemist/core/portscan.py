import subprocess
import re

def run_nmap(ip):
    """
    Basic port scan using nmap.
    """
    try:
        print(f"[*] Running Nmap on {ip}")
        result = subprocess.check_output(
            ["nmap", "-Pn", "-p-", "--open", ip],
            stderr=subprocess.DEVNULL
        ).decode()

        open_ports = re.findall(r"^(\d+)/tcp\s+open", result, re.MULTILINE)
        ports = list(map(int, open_ports))

        return {"ip": ip, "open_ports": ports}
    except subprocess.CalledProcessError as e:
        return None
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def run_nmap_detailed(ip):
    """
    Detailed Nmap scan with version detection.
    """
    try:
        result = subprocess.check_output(
            ["nmap", "-sS", "-sV", "-Pn", "-T4", "--top-ports", "100", ip],
            stderr=subprocess.DEVNULL
        ).decode()
        return result
    except subprocess.CalledProcessError:
        return "[!] Nmap failed."
    except Exception as e:
        return f"[!] Nmap error: {e}"
