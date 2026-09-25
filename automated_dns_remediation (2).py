import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import (
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    SMTP_SERVER,
    SMTP_PORT,
    FROM_EMAIL,
    TO_EMAIL,
    SEND_EMAIL,
    VYOS_SSH_PORT,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip, ping_device


# ============================================================
# Configuration
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")

TICKET_URL = f"{HELPDESK_BASE_URL}/api/tickets"

# These are the DNS servers that are considered correct
EXPECTED_DNS = [
    "10.10.10.10",
    "10.10.10.20",
]

# This must match the issue type used by the helpdesk service
ISSUE_TYPE = "DNS Compromise"


# ============================================================
# Device selection
# ============================================================

def get_monitored_devices():
    """
    Resolve DHCP devices and return devices that can be monitored.

    Devices without a usable IP are skipped.
    Open vSwitch devices are skipped.
    Devices without credentials are skipped.
    """

    devices = enumerate_devices(CSV_FILE)

    monitored = []

    for device in devices:

        address = device.get(
            "Device Address",
            ""
        ).strip()

        os_type = device.get(
            "OS",
            ""
        ).strip().lower()

        username = device.get(
            "Username",
            ""
        ).strip().lower()

        # Skip devices without usable addresses
        if not has_static_ip(address):
            continue

        # Skip switches
        if os_type in (
            "openvswitch",
            "switch",
        ):
            continue

        # Skip devices without SSH credentials
        if username in (
            "",
            "none",
        ):
            continue

        monitored.append(device)

    return monitored


# ============================================================
# SSH
# ============================================================

def run_ssh(
    host,
    port,
    username,
    password,
    command,
    timeout=8,
):
    """
    Execute a command over SSH.

    Paramiko is preferred when installed.
    sshpass is used as a fallback.
    """

    # --------------------------------------------------------
    # Try Paramiko first
    # --------------------------------------------------------

    try:
        import paramiko

        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        try:
            client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=timeout,
            )

            out = stdout.read().decode(
                "utf-8",
                errors="replace",
            )

            err = stderr.read().decode(
                "utf-8",
                errors="replace",
            )

            if out.strip():
                return True, out

            if err.strip():
                return False, err

            return True, ""

        finally:
            client.close()

    except ImportError:
        pass

    except Exception as exc:

        # If sshpass is unavailable, return the Paramiko error.
        if not shutil.which("sshpass"):
            return False, str(exc)

    # --------------------------------------------------------
    # Fallback to sshpass
    # --------------------------------------------------------

    if shutil.which("sshpass") and password:

        command_args = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={timeout}",
            "-p",
            str(port),
            f"{username}@{host}",
            command,
        ]

        try:

            result = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )

            output = (
                result.stdout
                if result.stdout.strip()
                else result.stderr
            )

            return (
                result.returncode == 0,
                output,
            )

        except Exception as exc:
            return False, str(exc)

    return (
        False,
        "Neither paramiko nor sshpass is available for SSH.",
    )


# ============================================================
# DNS Detection
# ============================================================

def detect_altered_dns(device):
    """
    Read the DNS configuration from a device.

    Returns:
        None
            DNS is correct, or device cannot be checked.

        str
            The detected DNS configuration when it differs
            from EXPECTED_DNS.
    """

    name = device["Device Name"]
    ip = device["Device Address"]

    os_type = device.get(
        "OS",
        "",
    ).strip()

    username = device.get(
        "Username",
        "",
    ).strip()

    password = device.get(
        "Password",
        "",
    )

    # VyOS SSH port comes from config.
    # Other devices use standard SSH port 22.
    if os_type.lower() == "vyos":
        port = VYOS_SSH_PORT
    else:
        port = 22

    print(
        f"\n  Checking DNS configuration on "
        f"{name} ({ip}) [OS: {os_type}]..."
    )

    # --------------------------------------------------------
    # Check availability first
    # --------------------------------------------------------

    if not ping_device(ip):

        print(
            f"  [SKIP] {name} ({ip}) is offline."
        )

        return None

    # --------------------------------------------------------
    # Get DNS configuration
    # --------------------------------------------------------

    if os_type.lower() == "vyos":

        command = (
            "/bin/vbash -ic "
            "'show configuration commands | "
            "match \"system name-server\"'"
        )

    else:

        command = "cat /etc/resolv.conf"

    success, output = run_ssh(
        ip,
        port,
        username,
        password,
        command,
    )

    if not success:

        print(
            f"  [WARN] Could not retrieve DNS configuration "
            f"from {name}:"
        )

        print(
            f"         {output.strip()}"
        )

        return None

    # --------------------------------------------------------
    # Extract IPv4 addresses
    # --------------------------------------------------------

    detected = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        output,
    )

    # Remove duplicates while preserving order
    detected = list(
        dict.fromkeys(detected)
    )

    # Ignore localhost DNS
    active = [
        dns
        for dns in detected
        if not dns.startswith("127.")
    ]

    print(
        f"  Current DNS: "
        f"{', '.join(active) if active else 'None detected'}"
    )

    print(
        f"  Expected DNS: "
        f"{', '.join(EXPECTED_DNS)}"
    )

    # --------------------------------------------------------
    # Compare actual DNS against expected DNS
    # --------------------------------------------------------

    actual_set = set(active)
    expected_set = set(EXPECTED_DNS)

    if actual_set == expected_set:

        print(
            f"  [OK] DNS configuration on {name} "
            f"is correct."
        )

        return None

    # --------------------------------------------------------
    # DNS configuration is altered
    # --------------------------------------------------------

    current_dns = (
        ", ".join(active)
        if active
        else "None detected"
    )

    print(
        f"  [ALERT] DNS configuration altered "
        f"on {name}: {current_dns}"
    )

    return current_dns


# ============================================================
# DNS Alert Email
# ============================================================

def build_altered_email(
    device,
    current_dns,
    expected_dns,
    timestamp,
):
    """
    Build the DNS Setting Altered Notification email.
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
Detected DNS Setting: {current_dns}
Expected DNS Setting: {expected_dns}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""

    return subject, body


def send_email(
    subject,
    body,
):
    """
    Send the DNS alert email.

    If SMTP is not configured, the email is displayed
    as a dry run instead.
    """

    message = MIMEMultipart()

    message["From"] = FROM_EMAIL
    message["To"] = TO_EMAIL
    message["Subject"] = subject

    message.attach(
        MIMEText(
            body,
            "plain",
        )
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "DNS SETTING ALTERED NOTIFICATION EMAIL"
    )

    print(
        "=" * 70
    )

    print(
        f"From    : {FROM_EMAIL}"
    )

    print(
        f"To      : {TO_EMAIL}"
    )

    print(
        f"Subject : {subject}"
    )

    print(
        "-" * 70
    )

    print(body)

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # Dry run
    # --------------------------------------------------------

    if not SEND_EMAIL or not SMTP_SERVER:

        print(
            "\n[DRY RUN] Email displayed. "
            "SMTP is not configured or SEND_EMAIL is disabled."
        )

        return True

    # --------------------------------------------------------
    # Send email
    # --------------------------------------------------------

    try:

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=10,
        ) as server:

            server.send_message(
                message
            )

        print(
            "\n[OK] Alert email sent successfully."
        )

        return True

    except Exception as exc:

        print(
            f"\n[WARN] Failed to send email: {exc}"
        )

        return False


# ============================================================
# Helpdesk - Get Tickets
# ============================================================

def get_tickets():
    """
    Retrieve tickets from the helpdesk API.
    """

    headers = {
        "Accept": "application/json",
    }

    if HELPDESK_TOKEN:

        headers["Authorization"] = (
            f"Bearer {HELPDESK_TOKEN}"
        )

    request = urllib.request.Request(
        TICKET_URL,
        headers=headers,
        method="GET",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

            data = json.loads(raw)

            # API may return a list directly
            if isinstance(data, list):
                return data

            # Or:
            # {"tickets": [...]}
            if isinstance(data, dict):

                tickets = data.get(
                    "tickets"
                )

                if isinstance(tickets, list):
                    return tickets

                # Or:
                # {"data": [...]}
                tickets = data.get(
                    "data"
                )

                if isinstance(tickets, list):
                    return tickets

            print(
                "\n  [WARN] Unexpected ticket API response."
            )

            return []

    except Exception as exc:

        print(
            f"\n  [WARN] Ticket service query failed "
            f"({TICKET_URL}): {exc}"
        )

        return []


# ============================================================
# Helpdesk - Find DNS Ticket
# ============================================================

def find_dns_ticket(
    tickets,
    device,
):
    """
    Find an existing OPEN DNS COMPROMISE ticket
    for the specific device.

    IMPORTANT:
    This deliberately ignores Device Unavailable tickets.
    """

    name = (
        device["Device Name"]
        .strip()
        .lower()
    )

    ip = (
        device["Device Address"]
        .strip()
    )

    for ticket in tickets:

        ticket_name = str(
            ticket.get(
                "device_name",
                "",
            )
        ).strip().lower()

        ticket_ip = str(
            ticket.get(
                "ip_address",
                "",
            )
        ).strip()

        issue_type = str(
            ticket.get(
                "issue_type",
                "",
            )
        ).strip().lower()

        status = str(
            ticket.get(
                "status",
                "",
            )
        ).strip().lower()

        # ----------------------------------------------------
        # Only DNS tickets
        # ----------------------------------------------------

        if issue_type != ISSUE_TYPE.lower():
            continue

        # ----------------------------------------------------
        # Ignore resolved tickets
        # ----------------------------------------------------

        if status == "resolved":
            continue

        # ----------------------------------------------------
        # Match device
        # ----------------------------------------------------

        if (
            ticket_name == name
            or ticket_ip == ip
        ):

            return ticket

    return None


# ============================================================
# Helpdesk - Create DNS Ticket
# ============================================================

def create_dns_ticket(
    device,
    detected_dns,
):
    """
    Create a DNS Compromise ticket when no open
    DNS ticket already exists.
    """

    name = device["Device Name"]
    ip = device["Device Address"]

    payload = json.dumps({
        "title": (
            f"DNS Setting Altered - {name}"
        ),

        "description": (
            f"DNS configuration altered on "
            f"{name} ({ip}). "
            f"Detected DNS: {detected_dns}. "
            f"Expected DNS: "
            f"{', '.join(EXPECTED_DNS)}."
        ),

        "device_name": name,

        "ip_address": ip,

        "issue_type": ISSUE_TYPE,

    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if HELPDESK_TOKEN:

        headers["Authorization"] = (
            f"Bearer {HELPDESK_TOKEN}"
        )

    request = urllib.request.Request(
        TICKET_URL,
        data=payload,
        headers=headers,
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

            ticket = json.loads(raw)

            print(
                f"  [OK] DNS ticket created."
            )

            return ticket

    except urllib.error.HTTPError as exc:

        raw = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        print(
            f"  [WARN] DNS ticket creation failed: "
            f"HTTP {exc.code}"
        )

        print(
            f"         {raw.strip()}"
        )

        return None

    except Exception as exc:

        print(
            f"  [WARN] DNS ticket creation failed: "
            f"{exc}"
        )

        return None


# ============================================================
# DNS Remediation
# ============================================================

def correct_dns(device):
    """
    Restore the device DNS configuration to EXPECTED_DNS.

    Returns:
        True  -> correction and verification succeeded
        False -> correction or verification failed
    """

    name = device["Device Name"]
    ip = device["Device Address"]

    os_type = device.get(
        "OS",
        "",
    ).strip()

    username = device.get(
        "Username",
        "",
    ).strip()

    password = device.get(
        "Password",
        "",
    )

    if os_type.lower() == "vyos":
        port = VYOS_SSH_PORT
    else:
        port = 22

    print(
        f"\n  --- Correcting DNS Configuration "
        f"on {name} ({ip}) ---"
    )

    # ========================================================
    # VyOS
    # ========================================================

    if os_type.lower() == "vyos":

        command = f"""
/bin/vbash -ic '
configure
delete system name-server
set system name-server {EXPECTED_DNS[0]}
set system name-server {EXPECTED_DNS[1]}
commit
save
exit
'
"""

        success, output = run_ssh(
            ip,
            port,
            username,
            password,
            command,
        )

        if not success:

            print(
                f"  [FAIL] Failed to modify DNS "
                f"configuration on {name}."
            )

            print(
                f"         {output.strip()}"
            )

            return False

        print(
            "  [OK] VyOS DNS configuration "
            "command completed."
        )

        # Command used to verify actual VyOS config
        verify_command = (
            "/bin/vbash -ic "
            "'show configuration commands | "
            "match \"system name-server\"'"
        )

    # ========================================================
    # Linux
    # ========================================================

    else:

        resolv_content = "\\n".join(
            f"nameserver {dns}"
            for dns in EXPECTED_DNS
        )

        command = (
            f"echo '{password}' | "
            f"sudo -S sh -c "
            f"'printf \"{resolv_content}\\n\" "
            f"> /etc/resolv.conf'"
        )

        success, output = run_ssh(
            ip,
            port,
            username,
            password,
            command,
        )

        if not success:

            print(
                f"  [FAIL] Failed to modify DNS "
                f"configuration on {name}."
            )

            print(
                f"         {output.strip()}"
            )

            return False

        print(
            "  [OK] Linux DNS configuration "
            "command completed."
        )

        verify_command = (
            "cat /etc/resolv.conf"
        )

    # ========================================================
    # Verify DNS
    # ========================================================

    verify_success, verify_output = run_ssh(
        ip,
        port,
        username,
        password,
        verify_command,
    )

    if not verify_success:

        print(
            f"  [FAIL] DNS verification failed "
            f"on {name}."
        )

        print(
            f"         {verify_output.strip()}"
        )

        return False

    print(
        f"\n  --- Verified DNS Configuration "
        f"on {name} ---"
    )

    print(
        verify_output.strip()
    )

    # --------------------------------------------------------
    # Extract IP addresses from verification output
    # --------------------------------------------------------

    verified_dns = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        verify_output,
    )

    verified_dns = list(
        dict.fromkeys(verified_dns)
    )

    # --------------------------------------------------------
    # Compare verification result
    # --------------------------------------------------------

    if set(verified_dns) == set(EXPECTED_DNS):

        print(
            f"\n  [SUCCESS] {name} DNS restored to "
            f"{', '.join(EXPECTED_DNS)}"
        )

        return True

    print(
        "\n  [FAIL] DNS verification does not "
        "match expected configuration."
    )

    print(
        f"  Expected: {', '.join(EXPECTED_DNS)}"
    )

    print(
        f"  Detected: "
        f"{', '.join(verified_dns) if verified_dns else 'None'}"
    )

    return False


# ============================================================
# Helpdesk - Resolve Ticket
# ============================================================

def resolve_ticket(
    ticket_id,
    device,
    timestamp,
):
    """
    Mark the DNS ticket as resolved.

    PATCH is attempted first.
    PUT is used as a fallback if PATCH is unsupported.
    """

    url = (
        f"{TICKET_URL}/{ticket_id}"
    )

    payload = json.dumps({

        "status": "resolved",

        "resolution": (
            f"DNS settings restored to "
            f"{', '.join(EXPECTED_DNS)}"
        ),

        "resolved_time": timestamp,

    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if HELPDESK_TOKEN:

        headers["Authorization"] = (
            f"Bearer {HELPDESK_TOKEN}"
        )

    for method in (
        "PATCH",
        "PUT",
    ):

        request = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method=method,
        )

        try:

            with urllib.request.urlopen(
                request,
                timeout=5,
            ) as response:

                raw = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                try:
                    ticket = json.loads(raw)
                except json.JSONDecodeError:
                    ticket = {
                        "message": raw
                    }

                print(
                    f"  [OK] Ticket #{ticket_id} "
                    f"updated -> status: resolved"
                )

                print(
                    f"       Device: "
                    f"{device['Device Name']} "
                    f"({device['Device Address']})"
                )

                return ticket

        except urllib.error.HTTPError as exc:

            # PATCH not supported.
            # Try PUT instead.
            if (
                exc.code == 405
                and method == "PATCH"
            ):
                continue

            raw = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            print(
                f"  [WARN] Ticket #{ticket_id} "
                f"update failed: HTTP {exc.code}"
            )

            if raw.strip():
                print(
                    f"         {raw.strip()}"
                )

            return None

        except Exception as exc:

            print(
                f"  [WARN] Ticket #{ticket_id} "
                f"update failed: {exc}"
            )

            return None

    return None


# ============================================================
# Display Tickets
# ============================================================

def show_ticket_entries(
    tickets,
):
    """
    Display DNS-related tickets for screenshot evidence.
    """

    print(
        "\n"
        + "=" * 90
    )

    print(
        "WEB SERVICE TICKETS "
        "(DNS COMPROMISE / RESOLVED)"
    )

    print(
        "=" * 90
    )

    header = (
        f"{'Ticket ID':<11} "
        f"{'Device Name':<15} "
        f"{'IP Address':<18} "
        f"{'Status':<12} "
        f"{'Issue Type':<20}"
    )

    print(header)

    print(
        "-" * len(header)
    )

    for ticket in tickets:

        issue_type = str(
            ticket.get(
                "issue_type",
                "",
            )
        )

        # Only display DNS tickets here
        if issue_type.lower() != ISSUE_TYPE.lower():
            continue

        ticket_id = (
            ticket.get("ticket_id")
            or ticket.get("id")
            or "?"
        )

        device_name = ticket.get(
            "device_name",
            "",
        )

        ip_address = ticket.get(
            "ip_address",
            "",
        )

        status = ticket.get(
            "status",
            "",
        )

        print(
            f"{str(ticket_id):<11} "
            f"{str(device_name):<15} "
            f"{str(ip_address):<18} "
            f"{str(status):<12} "
            f"{str(issue_type):<20}"
        )

    print(
        "=" * 90
    )


# ============================================================
# Main
# ============================================================

def main():

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    devices = get_monitored_devices()

    print(
        "=" * 70
    )

    print(
        "AUTOMATED DNS CONFIGURATION "
        "MONITORING & REMEDIATION"
    )

    print(
        f"Helpdesk API : {TICKET_URL}"
    )

    print(
        f"Expected DNS : "
        f"{', '.join(EXPECTED_DNS)}"
    )

    print(
        f"Devices to scan: {len(devices)}"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # Get current tickets
    # --------------------------------------------------------

    tickets = get_tickets()

    altered_count = 0
    remediated_count = 0
    failed_count = 0

    # ========================================================
    # Process devices
    # ========================================================

    for device in devices:

        name = device["Device Name"]
        ip = device["Device Address"]

        # ----------------------------------------------------
        # 1. Detect altered DNS
        # ----------------------------------------------------

        current_dns = detect_altered_dns(
            device
        )

        # DNS is correct or device unavailable
        if current_dns is None:
            continue

        altered_count += 1

        print(
            "\n"
            + "=" * 70
        )

        print(
            f"REMEDIATING: {name} ({ip})"
        )

        print(
            "=" * 70
        )

        # ----------------------------------------------------
        # 2. Send DNS alert email
        # ----------------------------------------------------

        subject, body = build_altered_email(
            device,
            current_dns,
            ", ".join(EXPECTED_DNS),
            timestamp,
        )

        send_email(
            subject,
            body,
        )

        # ----------------------------------------------------
        # 3. Find existing DNS ticket
        # ----------------------------------------------------

        ticket = find_dns_ticket(
            tickets,
            device,
        )

        ticket_id = None

        if ticket:

            ticket_id = (
                ticket.get("ticket_id")
                or ticket.get("id")
            )

            print(
                f"\n  [OK] Existing DNS ticket found: "
                f"#{ticket_id}"
            )

        else:

            print(
                "\n  No open DNS Compromise ticket "
                "found."
            )

            print(
                "  Creating a new DNS ticket..."
            )

            created_ticket = create_dns_ticket(
                device,
                current_dns,
            )

            if created_ticket:

                ticket_id = (
                    created_ticket.get(
                        "ticket_id"
                    )
                    or created_ticket.get(
                        "id"
                    )
                )

                if ticket_id:

                    print(
                        f"  [OK] Using new DNS "
                        f"ticket #{ticket_id}"
                    )

                    # Add newly created ticket to our
                    # local ticket list so future devices
                    # can see it during this execution.
                    tickets.append(
                        created_ticket
                    )

        # ----------------------------------------------------
        # 4. Correct DNS
        # ----------------------------------------------------

        remediated = correct_dns(
            device
        )

        # ----------------------------------------------------
        # 5. Only resolve after successful verification
        # ----------------------------------------------------

        if not remediated:

            failed_count += 1

            print(
                f"\n  [FAIL] DNS remediation failed "
                f"for {name}."
            )

            print(
                "  The DNS ticket will remain open."
            )

            continue

        remediated_count += 1

        # ----------------------------------------------------
        # 6. Resolve DNS ticket
        # ----------------------------------------------------

        if ticket_id is None:

            print(
                "\n  [WARN] DNS was successfully "
                "corrected, but no ticket ID "
                "is available to resolve."
            )

            continue

        print(
            "\n  --- Updating DNS Ticket "
            "in Web Service ---"
        )

        resolve_ticket(
            ticket_id,
            device,
            timestamp,
        )

    # ========================================================
    # Summary
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SCAN COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"DNS altered devices : {altered_count}"
    )

    print(
        f"Successfully fixed  : {remediated_count}"
    )

    print(
        f"Failed remediation  : {failed_count}"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # Refresh tickets for screenshot evidence
    # --------------------------------------------------------

    updated_tickets = get_tickets()

    if updated_tickets:

        show_ticket_entries(
            updated_tickets
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()