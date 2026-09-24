import json
import os
import smtplib
import sys
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import paramiko

from config import (
    TICKET_URL,
    HELPDESK_TOKEN,
    SMTP_SERVER,
    SMTP_PORT,
    FROM_EMAIL,
    TO_EMAIL,
    SEND_EMAIL,
)

# ------------------------------------------------------------
# IMPORT EXISTING PROJECT MODULES
# ------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip, ping_device


CSV_FILE = os.path.join(
    SCRIPT_DIR,
    "network_devices.csv",
)

# Correct DNS servers for the lab
EXPECTED_DNS = [
    "10.10.10.10",
    "10.10.10.20",
]

ISSUE_TYPE = "DNS Compromise"

# Server devices that should be checked for altered DNS.
# We are NOT saying these are broken.
# The script checks them and discovers which ones are altered.
SERVER_NAMES = {
    "API",
    "DB",
    "DNS1",
    "DNS2",
    "SVR1",
    "SVR2",
}


# ============================================================
# GET SERVER DEVICES
# ============================================================

def get_server_devices():
    """
    Use enumerate_devices.py to read network_devices.csv.

    enumerate_devices() already resolves DHCP addresses.
    Only server devices used for DNS monitoring are returned.
    """

    devices = enumerate_devices(CSV_FILE)

    servers = []

    for device in devices:
        name = device["Device Name"].strip().upper()
        address = device["Device Address"].strip()

        if name not in SERVER_NAMES:
            continue

        if not has_static_ip(address):
            continue

        servers.append(device)

    return servers


# ============================================================
# SSH
# ============================================================

def create_ssh_client(device):
    """
    Connect to the device using credentials from network_devices.csv.
    """

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=device["Device Address"].strip(),
        username=device["Username"].strip(),
        password=device["Password"].strip(),
        timeout=8,
        allow_agent=False,
        look_for_keys=False,
    )

    return client


def run_ssh_command(device, command):
    """
    Execute a command on a remote server.
    """

    client = None

    try:
        client = create_ssh_client(device)

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=10,
        )

        output = stdout.read().decode(
            errors="replace"
        ).strip()

        error = stderr.read().decode(
            errors="replace"
        ).strip()

        status = stdout.channel.recv_exit_status()

        return output, error, status

    except Exception as exc:

        return "", str(exc), 1

    finally:

        if client:
            client.close()


# ============================================================
# READ DNS CONFIGURATION
# ============================================================

def read_dns_configuration(device):
    """
    Read /etc/resolv.conf from the remote server.

    Returns:
        list of DNS servers
        raw resolv.conf output
    """

    output, error, status = run_ssh_command(
        device,
        "cat /etc/resolv.conf",
    )

    if status != 0:

        print(
            f"  [ERROR] Unable to read DNS configuration: "
            f"{error}"
        )

        return None, None

    dns_servers = []

    for line in output.splitlines():

        line = line.strip()

        if line.startswith("nameserver"):

            parts = line.split()

            if len(parts) >= 2:
                dns_servers.append(parts[1])

    return dns_servers, output


def detect_altered_dns(device):
    """
    Display and return the actual DNS configuration.
    """

    name = device["Device Name"]
    ip = device["Device Address"]

    print()
    print(
        f"--- Checking DNS Configuration "
        f"on {name} ({ip}) ---"
    )

    dns_servers, raw_output = read_dns_configuration(
        device
    )

    if dns_servers is None:
        return None

    print("$ cat /etc/resolv.conf")

    for line in raw_output.splitlines():
        print(f"> {line}")

    print()

    if dns_servers:
        print(
            "Detected DNS: "
            + ", ".join(dns_servers)
        )
    else:
        print("Detected DNS: NONE")

    return dns_servers


def dns_is_altered(current_dns):
    """
    Return True if the current DNS does not match
    the expected DNS configuration.
    """

    if not current_dns:
        return True

    return set(current_dns) != set(EXPECTED_DNS)


# ============================================================
# EMAIL
# ============================================================

def build_altered_email(
    device,
    current_dns,
    timestamp,
):
    """
    Build the DNS Setting Altered notification.
    """

    name = device["Device Name"]
    ip = device["Device Address"]

    subject = (
        f"DNS Configuration Alert: "
        f"{name} ({ip})"
    )

    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {", ".join(current_dns)}
Expected DNS Setting: {", ".join(EXPECTED_DNS)}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""

    return subject, body


def send_email(subject, body):
    """
    Send the altered-DNS notification.

    If SMTP is disabled, display the email for testing.
    """

    msg = MIMEMultipart()

    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject

    msg.attach(
        MIMEText(body, "plain")
    )

    print()
    print("=" * 70)
    print("DNS SETTING ALTERED NOTIFICATION EMAIL")
    print("=" * 70)

    print(f"From    : {FROM_EMAIL}")
    print(f"To      : {TO_EMAIL}")
    print(f"Subject : {subject}")

    print("-" * 70)

    print(body)

    print("=" * 70)

    if not SEND_EMAIL or not SMTP_SERVER:

        print(
            "\n[DRY RUN] Email displayed because "
            "SMTP is not configured or SEND_EMAIL "
            "is disabled."
        )

        return

    try:

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=10,
        ) as server:

            server.send_message(msg)

        print(
            "\n[OK] DNS alert email sent successfully."
        )

    except Exception as exc:

        print(
            f"\n[ERROR] Failed to send email: {exc}"
        )


# ============================================================
# CORRECT DNS
# ============================================================

def correct_dns(device):
    """
    Correct /etc/resolv.conf on the remote server.

    The password comes from network_devices.csv.
    After making the change, the function reads the file again
    to verify that the expected DNS settings are present.
    """

    name = device["Device Name"]
    ip = device["Device Address"]
    password = device["Password"].strip()

    print()
    print(
        f"--- Correcting DNS Configuration "
        f"on {name} ({ip}) ---"
    )

    new_dns_config = ""

    for dns in EXPECTED_DNS:
        new_dns_config += f"nameserver {dns}\n"

    client = None

    try:

        client = create_ssh_client(device)

        stdin, stdout, stderr = client.exec_command(
            "sudo -S -p '' tee /etc/resolv.conf >/dev/null",
            timeout=10,
        )

        # Send sudo password
        stdin.write(password + "\n")

        # Send correct DNS configuration
        stdin.write(new_dns_config)

        stdin.flush()
        stdin.channel.shutdown_write()

        status = stdout.channel.recv_exit_status()

        error = stderr.read().decode(
            errors="replace"
        ).strip()

        if status != 0:

            print(
                f"[ERROR] DNS correction failed: {error}"
            )

            return False

    except Exception as exc:

        print(
            f"[ERROR] Unable to correct DNS: {exc}"
        )

        return False

    finally:

        if client:
            client.close()

    # --------------------------------------------------------
    # VERIFY CORRECTION
    # --------------------------------------------------------

    print()
    print("--- Verifying DNS Correction ---")

    corrected_dns, raw_output = read_dns_configuration(
        device
    )

    if corrected_dns is None:

        print(
            "[ERROR] Unable to verify DNS correction."
        )

        return False

    print("$ cat /etc/resolv.conf")

    for line in raw_output.splitlines():
        print(f"> {line}")

    if set(corrected_dns) == set(EXPECTED_DNS):

        print()
        print(
            f"[OK] {name} DNS corrected successfully."
        )

        print(
            "Correct DNS: "
            + ", ".join(corrected_dns)
        )

        return True

    print()
    print(
        f"[ERROR] DNS verification failed on {name}."
    )

    print(
        "Expected: "
        + ", ".join(EXPECTED_DNS)
    )

    print(
        "Detected: "
        + ", ".join(corrected_dns)
    )

    return False


# ============================================================
# TICKET FUNCTIONS
# ============================================================

def get_tickets():

    request = urllib.request.Request(
        TICKET_URL,
        headers={
            "Authorization":
                f"Bearer {HELPDESK_TOKEN}",
        },
        method="GET",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            data = json.loads(
                response.read()
            )

            if isinstance(data, list):
                return data

            if isinstance(data, dict):
                return data.get("tickets", [])

            return []

    except urllib.error.URLError as exc:

        print(
            f"\n[WARN] Cannot reach ticket service: "
            f"{exc.reason}"
        )

        return []


def find_ticket(tickets, device):
    """
    Find an existing unresolved DNS ticket for this device.
    """

    name = device["Device Name"]

    for ticket in tickets:

        if (
            ticket.get("device_name") == name
            and
            ticket.get("issue_type") == ISSUE_TYPE
        ):

            status = str(
                ticket.get("status", "")
            ).lower()

            if status != "resolved":
                return ticket

    return None


def create_ticket(device):
    """
    Create a DNS compromise ticket if one does not already exist.
    """

    payload = json.dumps(
        {
            "device_name":
                device["Device Name"],

            "ip_address":
                device["Device Address"],

            "issue_type":
                ISSUE_TYPE,
        }
    ).encode()

    request = urllib.request.Request(
        TICKET_URL,
        data=payload,
        headers={
            "Content-Type":
                "application/json",

            "Authorization":
                f"Bearer {HELPDESK_TOKEN}",
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            ticket = json.loads(
                response.read()
            )

            print(
                f"[OK] DNS ticket created for "
                f"{device['Device Name']}."
            )

            return ticket

    except urllib.error.URLError as exc:

        print(
            f"[WARN] Cannot create ticket: "
            f"{exc.reason}"
        )

        return None


def get_ticket_id(ticket):

    if not ticket:
        return None

    return (
        ticket.get("ticket_id")
        or ticket.get("id")
    )


def resolve_ticket(
    ticket_id,
    device,
    timestamp,
):
    """
    Mark the ticket resolved only AFTER DNS has been corrected
    and verified.
    """

    url = f"{TICKET_URL}/{ticket_id}"

    payload = json.dumps(
        {
            "status": "resolved",

            "resolution":
                "DNS setting corrected to expected configuration",

            "resolved_time":
                timestamp,
        }
    ).encode()

    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type":
                "application/json",

            "Authorization":
                f"Bearer {HELPDESK_TOKEN}",
        },
        method="PATCH",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            ticket = json.loads(
                response.read()
            )

            print(
                f"[OK] Ticket #{ticket_id} updated "
                f"to {ticket.get('status')}."
            )

            return ticket

    except urllib.error.URLError as exc:

        print(
            f"[WARN] Cannot update ticket "
            f"#{ticket_id}: {exc.reason}"
        )

        return None


# ============================================================
# SHOW DNS TICKETS
# ============================================================

def show_ticket_entries(tickets):

    print()
    print("=" * 80)
    print("DNS COMPROMISE TICKETS")
    print("=" * 80)

    header = (
        f"{'Ticket ID':<12} "
        f"{'Device':<14} "
        f"{'IP Address':<18} "
        f"{'Status':<12} "
        f"{'Issue Type':<18}"
    )

    print(header)
    print("-" * len(header))

    for ticket in tickets:

        if ticket.get("issue_type") != ISSUE_TYPE:
            continue

        ticket_id = (
            ticket.get("ticket_id")
            or ticket.get("id")
            or ""
        )

        print(
            f"{str(ticket_id):<12} "
            f"{ticket.get('device_name', ''):<14} "
            f"{ticket.get('ip_address', ''):<18} "
            f"{ticket.get('status', ''):<12} "
            f"{ticket.get('issue_type', ''):<18}"
        )

    print("=" * 80)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("AUTOMATED DNS CONFIGURATION MONITOR")
    print("=" * 70)

    print(
        "Check availability -> Detect DNS change -> "
        "Notify -> Correct -> Verify -> Resolve ticket"
    )

    print("=" * 70)

    # enumerate_devices.py does the device/IP enumeration
    devices = get_server_devices()

    tickets = get_tickets()

    altered_count = 0
    corrected_count = 0

    for device in devices:

        name = device["Device Name"]
        ip = device["Device Address"]

        print()
        print("=" * 70)
        print(f"DEVICE: {name} ({ip})")
        print("=" * 70)

        # ----------------------------------------------------
        # REUSE monitor_device_availability.py
        # ----------------------------------------------------

        print(
            f"Checking availability of {name}..."
        )

        if not ping_device(ip):

            print(
                f"[OFFLINE] {name} ({ip}) is unavailable."
            )

            print(
                "Skipping DNS check because the device "
                "cannot currently be reached."
            )

            # C2 handles the unavailable-device notification.
            continue

        print(
            f"[ONLINE] {name} ({ip}) is available."
        )

        # ----------------------------------------------------
        # CHECK REAL DNS
        # ----------------------------------------------------

        current_dns = detect_altered_dns(
            device
        )

        if current_dns is None:

            print(
                f"[WARN] Could not inspect DNS on {name}."
            )

            continue

        # ----------------------------------------------------
        # DNS IS NORMAL
        # ----------------------------------------------------

        if not dns_is_altered(current_dns):

            print()
            print(
                f"[OK] {name} DNS configuration "
                f"has not been altered."
            )

            print(
                "DNS: "
                + ", ".join(current_dns)
            )

            continue

        # ----------------------------------------------------
        # ALTERED DNS FOUND
        # ----------------------------------------------------

        altered_count += 1

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        print()
        print(
            f"[ALERT] ALTERED DNS DETECTED ON {name}"
        )

        print(
            "Current DNS : "
            + ", ".join(current_dns)
        )

        print(
            "Expected DNS: "
            + ", ".join(EXPECTED_DNS)
        )

        # ----------------------------------------------------
        # EMAIL STAKEHOLDERS
        # ----------------------------------------------------

        subject, body = build_altered_email(
            device,
            current_dns,
            timestamp,
        )

        send_email(
            subject,
            body,
        )

        # ----------------------------------------------------
        # FIND OR CREATE TICKET
        # ----------------------------------------------------

        print()
        print("--- DNS Ticket ---")

        ticket = find_ticket(
            tickets,
            device,
        )

        if ticket is None:

            print(
                f"No open {ISSUE_TYPE} ticket "
                f"found for {name}."
            )

            print(
                "Creating DNS ticket..."
            )

            ticket = create_ticket(
                device
            )

            if ticket:
                tickets.append(ticket)

        else:

            print(
                f"Existing DNS ticket found for {name}."
            )

        ticket_id = get_ticket_id(
            ticket
        )

        # ----------------------------------------------------
        # CORRECT DNS
        # ----------------------------------------------------

        corrected = correct_dns(
            device
        )

        if not corrected:

            print()
            print(
                f"[ERROR] DNS correction failed "
                f"on {name}."
            )

            print(
                "Ticket will remain open."
            )

            continue

        corrected_count += 1

        # ----------------------------------------------------
        # RESOLVE TICKET
        # ----------------------------------------------------

        if ticket_id is not None:

            resolved_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print()
            print(
                "--- Updating Ticket as Resolved ---"
            )

            resolve_ticket(
                ticket_id,
                device,
                resolved_time,
            )

        else:

            print(
                "[WARN] DNS was corrected but no "
                "ticket ID was available."
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("DNS MONITORING SUMMARY")
    print("=" * 70)

    print(
        f"Servers checked              : "
        f"{len(devices)}"
    )

    print(
        f"Altered DNS devices detected : "
        f"{altered_count}"
    )

    print(
        f"Devices successfully corrected: "
        f"{corrected_count}"
    )

    print("=" * 70)

    # Refresh ticket table after changes
    tickets = get_tickets()

    show_ticket_entries(
        tickets
    )


if __name__ == "__main__":
    main()
