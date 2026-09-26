from datetime import datetime
import os
import re
import sys
import paramiko
from config import EXPECTED_DNS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enumerate_devices import enumerate_devices

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
LOG_FILE = os.path.join(SCRIPT_DIR, "dns_status.log")

IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def get_device_dns(ssh_client):
    cmd = "resolvectl dns 2>/dev/null; grep '^nameserver' /etc/resolv.conf 2>/dev/null"
    _, stdout, _ = ssh_client.exec_command(cmd, timeout=5)
    output = stdout.read().decode("utf-8", errors="replace").strip()

    detected_dns = []
    for line in output.splitlines():
        if "Link" in line or "nameserver" in line:
            parts = line.replace("nameserver", "").split(":")[-1].strip().split()
            for part in parts:
                if IP_PATTERN.match(part) and not part.startswith("127.") and part not in detected_dns:
                    detected_dns.append(part)
    return detected_dns

def main():
    devices = enumerate_devices(CSV_FILE)
    
    with open(LOG_FILE, "a") as f:
        for dev in devices:
            name = dev["Device Name"].strip()
            ip = dev["Device Address"].strip()
            os_type = dev.get("OS", "").strip().lower()
            user = dev.get("Username", "ubuntu").strip()
            password = dev.get("Password", "ubuntu").strip()

            if os_type != "ubuntu" or not IP_PATTERN.match(ip):
                continue
            if name.upper() in ["DNS1", "DNS2", "SMTP"]:
                continue

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                ssh.connect(ip, port=22, username=user, password=password, timeout=4)
                current_dns = get_device_dns(ssh)

                if set(current_dns) == set(EXPECTED_DNS):
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    entry = f"[{now_str}] Device: {name} ({ip}) - DNS service is functioning correctly and has not been altered."
                    print(entry)
                    f.write(entry + "\n")
            except Exception as err:
                print(f"Could not connect to {name} ({ip}): {err}")
            finally:
                ssh.close()

if __name__ == "__main__":
    main()
