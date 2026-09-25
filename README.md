import json
import os
import re
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


# ============================================================
# PROJECT IMPORTS
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from enumerate_devices import enumerate_devices
import monitor_device_availability as availability


CSV_FILE = os.path.join(
    SCRIPT_DIR,
    "network_devices.csv",
)


# ============================================================
# LAB SETTINGS
# ============================================================

EXPECTED_DNS = [
    "10.10.10.10",
    "10.10.10.20",
]

ISSUE_TYPE = "DNS Compromise"

# Servers in this GNS3 lab that should have their DNS checked.
SERVER_NAMES = {
    "API",
    "DB",
    "DNS1",
    "DNS2",
    "SVR1",
    "SVR2",
}

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


# ============================================================
# DEVICE ENUMERATION
# ============================================================

def get_server_devices():
    """
    Uses enumerate_devices.py.

    enumerate_devices.py already reads network_devices.csv
    and resolves DHCP addresses where needed.
    """

    devices = enumerate_devices(CSV_FILE)

    servers = []

    for device in devices:
        name = device["Device Name"].strip().upper()

        if name in SERVER_NAMES:
            servers.append(device)

    return servers


# ============================================================
# SSH CONNECTION
# ============================================================

def create_ssh_client(device):
    """
    Connect to an Ubuntu device using credentials from
    network_devices.csv.
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
    Execute a normal remote command.

    Returns:
        output
        error
        exit_status
    """

    client = None

    try:
        client = create_ssh_client(device)

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=15,
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


def run_sudo_command(device, command):
    """
    Execute a command with sudo using the password
    stored in network_devices.csv.
    """

    client = None

    try:
        client = create_ssh_client(device)

        password = device["Password"].strip()

        full_command = (
            f"sudo -S -p '' {command}"
        )

        stdin, stdout, stderr = client.exec_command(
            full_command,
            timeout=15,
        )

        stdin.write(password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()

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
# NETWORK INTERFACE
# ============================================================

def get_primary_interface(device):
    """
    Determine which interface the server uses for its
    default route.

    Example result:
        eth0
    """

    command = (
        "ip route show default | "
        "awk '{print $5; exit}'"
    )

    output, error, status = run_ssh_command(
        device,
        command,
    )

    if status != 0 or not output.strip():

        print(
            f"[ERROR] Could not determine the "
            f"network interface for "
            f"{device['Device Name']}."
        )

        if error:
            print(error)

        return None

    return output.strip().splitlines()[0]


# ============================================================
# READ REAL DNS CONFIGURATION
# ============================================================

def read_dns_configuration(device):
    """
    The lab systems use systemd-resolved.

    /etc/resolv.conf may only show:
        nameserver 127.0.0.53

    Therefore this function uses:
        resolvectl dns

    to obtain the actual upstream DNS servers.
    """

    interface = get_primary_interface(device)

    if not interface:
        return None, None, None

    output, error, status = run_ssh_command(
        device,
        "resolvectl dns",
    )

    if status != 0:

        print(
            f"[ERROR] Could not read DNS configuration "
            f"on {device['Device Name']}."
        )

        if error:
            print(error)

        return None, None, interface

    dns_servers = []

    for line in output.splitlines():

        # We only care about the default interface.
        #
        # Example:
        # Link 2 (eth0): 10.10.10.10 10.10.10.20

        if f"({interface})" not in line:
            continue

        addresses = IP_PATTERN.findall(line)

        for address in addresses:

            # Ignore systemd local stub if it ever appears.
            if address == "127.0.0.53":
                continue

            if address not in dns_servers:
                dns_servers.append(address)

    return dns_servers, output, interface


# ============================================================
# DETECT ALTERED DNS
# ============================================================

def dns_is_altered(current_dns):
    """
    The DNS setting is considered altered whenever the
    actual DNS servers do not match the expected lab DNS
    servers.

    This catches addresses such as:
        203.0.113.10

    instead of assuming the rogue DNS must be 8.8.8.8.
    """

    if not current_dns:
        return True

    return set(current_dns) != set(EXPECTED_DNS)


# ============================================================
# DNS ALTERED EMAIL
# ============================================================

def build_dns_email(
    device,
    current_dns,
    timestamp,
):
    name = device["Device Name"]
    ip = device["Device Address"]

    detected = (
        ", ".join(current_dns)
        if current_dns
        else "No valid DNS server detected"
    )

    expected = ", ".join(EXPECTED_DNS)

    subject = (
        f"DNS Configuration Alert: "
        f"{name} ({ip})"
    )

    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {detected}
Expected DNS Setting: {expected}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""

    return subject, body


def send_dns_email(subject, body):
    """
    Send the DNS Setting Altered notification.
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

        return False

    try:

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=10,
        ) as server:

            server.send_message(msg)

        print()
        print(
            "[OK] DNS alteration email sent successfully."
        )

        return True

    except Exception as exc:

        print()
        print(
            f"[ERROR] DNS email failed: {exc}"
        )

        return False


# ============================================================
# CORRECT DNS
# ============================================================

def correct_dns(device):
    """
    Correct the real systemd-resolved DNS configuration.

    We DO NOT edit /etc/resolv.conf because this lab uses
    systemd-resolved.

    Instead we run:

        resolvectl dns INTERFACE 10.10.10.10 10.10.10.20

    and verify the result afterward.
    """

    name = device["Device Name"]

    interface = get_primary_interface(device)

    if not interface:
        return False

    print()
    print(
        f"--- Correcting DNS Configuration on {name} ---"
    )

    print(
        f"Network Interface: {interface}"
    )

    command = (
        f"resolvectl dns {interface} "
        f"{EXPECTED_DNS[0]} "
        f"{EXPECTED_DNS[1]}"
    )

    output, error, status = run_sudo_command(
        device,
        command,
    )

    if status != 0:

        print(
            f"[ERROR] Failed to change DNS on {name}."
        )

        if error:
            print(error)

        return False

    # Flush DNS cache after correction.
    run_sudo_command(
        device,
        "resolvectl flush-caches",
    )

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    corrected_dns, raw_output, interface = (
        read_dns_configuration(device)
    )

    print()
    print("--- DNS Configuration After Correction ---")

    if raw_output:
        print(raw_output)

    print()

    if corrected_dns:
        print(
            "Detected DNS after correction: "
            + ", ".join(corrected_dns)
        )
    else:
        print(
            "Detected DNS after correction: NONE"
        )

    if (
        corrected_dns
        and set(corrected_dns) == set(EXPECTED_DNS)
    ):

        print()
        print(
            f"[OK] {name} DNS corrected successfully."
        )

        return True

    print()
    print(
        f"[ERROR] DNS correction verification "
        f"failed on {name}."
    )

    print(
        "Expected DNS: "
        + ", ".join(EXPECTED_DNS)
    )

    print(
        "Detected DNS: "
        + (
            ", ".join(corrected_dns)
            if corrected_dns
            else "NONE"
        )
    )

    return False


# ============================================================
# TICKET SERVICE
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
            f"[WARN] Cannot reach ticket service: "
            f"{exc.reason}"
        )

        return []


def find_dns_ticket(
    tickets,
    device,
):
    """
    Find an existing unresolved DNS Compromise ticket.
    """

    device_name = device["Device Name"]

    for ticket in tickets:

        if (
            ticket.get("device_name") == device_name
            and
            ticket.get("issue_type") == ISSUE_TYPE
        ):

            status = str(
                ticket.get("status", "")
            ).lower()

            if status != "resolved":
                return ticket

    return None


def create_dns_ticket(device):
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
            f"[WARN] Cannot create DNS ticket: "
            f"{exc.reason}"
        )

        return None


def get_ticket_id(ticket):
    if not ticket:
        return None

    return (
        ticket.get("ticket_id")
        or
        ticket.get("id")
    )


def resolve_ticket(
    ticket_id,
    device,
):
    """
    Resolve the ticket only after the DNS correction
    has been successfully verified.
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    url = f"{TICKET_URL}/{ticket_id}"

    payload = json.dumps(
        {
            "status": "resolved",

            "resolution":
                "DNS configuration corrected to "
                "10.10.10.10 and 10.10.10.20",

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
                f"[OK] Ticket #{ticket_id} "
                f"updated to resolved."
            )

            return ticket

    except urllib.error.URLError as exc:

        print(
            f"[WARN] Cannot resolve ticket "
            f"#{ticket_id}: {exc.reason}"
        )

        return None


# ============================================================
# MAIN
# ============================================================

def main():
    """
    LAB WORKFLOW

    1. enumerate_devices.py gets device information.
    2. monitor_device_availability.py checks ping availability.
    3. Offline server -> send existing unavailable-device email.
    4. Online server -> read actual systemd-resolved DNS.
    5. Correct DNS -> no action.
    6. Altered DNS -> send DNS altered email.
    7. Create/find DNS ticket.
    8. Correct DNS using resolvectl.
    9. Verify correction.
    10. Resolve ticket only after verification.
    """

    devices = get_server_devices()

    tickets = get_tickets()

    offline_count = 0
    altered_count = 0
    corrected_count = 0

    print("=" * 70)
    print("AUTOMATED DNS REMEDIATION")
    print("=" * 70)

    print(
        "Availability -> DNS Detection -> Notification -> "
        "Correction -> Verification -> Ticket Resolution"
    )

    print("=" * 70)

    for device in devices:

        name = device["Device Name"]
        ip = device["Device Address"]

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        print()
        print("=" * 70)
        print(
            f"DEVICE: {name} ({ip})"
        )
        print("=" * 70)

        # ====================================================
        # 1. DEVICE AVAILABILITY
        # ====================================================

        online = availability.ping_device(ip)

        if not online:

            offline_count += 1

            print(
                f"[OFFLINE] {name} ({ip})"
            )

            # Reuse existing C2 notification code.
            subject, body = availability.build_email(
                device,
                timestamp,
            )

            availability.send_email(
                subject,
                body,
            )

            # Cannot inspect DNS on an offline device.
            continue

        print(
            f"[ONLINE] {name} ({ip})"
        )

        # ====================================================
        # 2. READ REAL DNS
        # ====================================================

        current_dns, raw_dns, interface = (
            read_dns_configuration(device)
        )

        if current_dns is None:

            print(
                f"[WARN] DNS configuration could not "
                f"be inspected on {name}."
            )

            continue

        print()
        print(
            f"Default Interface: {interface}"
        )

        print()
        print(
            "Current DNS Configuration:"
        )

        print(raw_dns)

        print()

        print(
            "Detected Upstream DNS: "
            + (
                ", ".join(current_dns)
                if current_dns
                else "NONE"
            )
        )

        # ====================================================
        # 3. DNS IS CORRECT
        # ====================================================

        if not dns_is_altered(current_dns):

            print()
            print(
                f"[OK] {name} DNS configuration "
                f"is correct."
            )

            continue

        # ====================================================
        # 4. ALTERED DNS
        # ====================================================

        altered_count += 1

        print()
        print(
            f"[ALERT] ALTERED DNS DETECTED ON {name}"
        )

        print(
            "Current DNS : "
            + (
                ", ".join(current_dns)
                if current_dns
                else "NONE"
            )
        )

        print(
            "Expected DNS: "
            + ", ".join(EXPECTED_DNS)
        )

        # ====================================================
        # 5. DNS ALTERED EMAIL
        # ====================================================

        subject, body = build_dns_email(
            device,
            current_dns,
            timestamp,
        )

        send_dns_email(
            subject,
            body,
        )

        # ====================================================
        # 6. FIND OR CREATE TICKET
        # ====================================================

        print()
        print(
            "--- DNS Ticket ---"
        )

        ticket = find_dns_ticket(
            tickets,
            device,
        )

        if ticket is None:

            print(
                f"No open {ISSUE_TYPE} ticket "
                f"found for {name}."
            )

            print(
                "Creating ticket..."
            )

            ticket = create_dns_ticket(
                device
            )

            if ticket:
                tickets.append(ticket)

        else:

            print(
                f"Existing DNS ticket found "
                f"for {name}."
            )

        ticket_id = get_ticket_id(
            ticket
        )

        # ====================================================
        # 7. CORRECT DNS
        # ====================================================

        fixed = correct_dns(
            device
        )

        if not fixed:

            print()
            print(
                f"[ERROR] {name} DNS was NOT fixed."
            )

            print(
                "Ticket will remain unresolved."
            )

            continue

        corrected_count += 1

        # ====================================================
        # 8. RESOLVE TICKET
        # ====================================================

        if ticket_id is not None:

            print()
            print(
                "--- Updating Ticket as Resolved ---"
            )

            resolve_ticket(
                ticket_id,
                device,
            )

        else:

            print()
            print(
                "[WARN] DNS was corrected, but "
                "there was no ticket ID to resolve."
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("AUTOMATED DNS REMEDIATION SUMMARY")
    print("=" * 70)

    print(
        f"Servers checked               : "
        f"{len(devices)}"
    )

    print(
        f"Offline servers               : "
        f"{offline_count}"
    )

    print(
        f"Altered DNS configurations    : "
        f"{altered_count}"
    )

    print(
        f"Successfully corrected DNS    : "
        f"{corrected_count}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
