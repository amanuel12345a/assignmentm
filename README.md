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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from enumerate_devices import enumerate_devices
import monitor_device_availability as availability


CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")

ROGUE_DNS = "8.8.8.8"

EXPECTED_DNS = [
    "10.10.10.10",
    "10.10.10.20",
]

ISSUE_TYPE = "DNS Compromise"

SERVER_NAMES = {
    "API",
    "DB",
    "DNS1",
    "DNS2",
    "SVR1",
    "SVR2",
}


def get_server_devices():
    devices = enumerate_devices(CSV_FILE)

    servers = []

    for device in devices:
        name = device["Device Name"].strip().upper()

        if name in SERVER_NAMES:
            servers.append(device)

    return servers


def create_ssh_client(device):
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


def read_dns_configuration(device):
    output, error, status = run_ssh_command(
        device,
        "cat /etc/resolv.conf",
    )

    if status != 0:
        print(
            f"[ERROR] Unable to read DNS on "
            f"{device['Device Name']}: {error}"
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


def dns_is_altered(current_dns):
    if current_dns is None:
        return False

    return ROGUE_DNS in current_dns


def build_dns_email(device, current_dns, timestamp):
    name = device["Device Name"]
    ip = device["Device Address"]

    subject = (
        f"DNS Configuration Alert: {name} ({ip})"
    )

    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {", ".join(current_dns)}
Unauthorized DNS Setting: {ROGUE_DNS}
Expected DNS Setting: {", ".join(EXPECTED_DNS)}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""

    return subject, body


def send_dns_email(subject, body):
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
            "SMTP is not configured or SEND_EMAIL is disabled."
        )
        return False

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

        return True

    except Exception as exc:
        print(
            f"\n[ERROR] Failed to send DNS email: {exc}"
        )
        return False


def correct_dns(device):
    name = device["Device Name"]
    password = device["Password"].strip()

    print()
    print(
        f"--- Correcting DNS Configuration on {name} ---"
    )

    client = None

    try:
        client = create_ssh_client(device)

        command = (
            "sudo -S -p '' sh -c "
            "\"rm -f /etc/resolv.conf && "
            "printf 'nameserver 10.10.10.10\\n"
            "nameserver 10.10.10.20\\n' "
            "> /etc/resolv.conf\""
        )

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=10,
        )

        stdin.write(password + "\n")
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
            f"[ERROR] DNS correction failed: {exc}"
        )
        return False

    finally:
        if client:
            client.close()

    corrected_dns, output = read_dns_configuration(
        device
    )

    print()
    print("--- DNS Configuration After Correction ---")

    if output:
        print(output)

    if (
        corrected_dns
        and ROGUE_DNS not in corrected_dns
        and "10.10.10.10" in corrected_dns
        and "10.10.10.20" in corrected_dns
    ):
        print()
        print(
            f"[OK] {name} DNS corrected successfully."
        )
        return True

    print()
    print(
        f"[ERROR] {name} DNS was not corrected."
    )
    print(
        f"Current DNS: {corrected_dns}"
    )

    return False


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


def find_dns_ticket(tickets, device):
    for ticket in tickets:

        if (
            ticket.get("device_name")
            == device["Device Name"]
            and
            ticket.get("issue_type")
            == ISSUE_TYPE
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
            f"[WARN] Cannot create ticket: "
            f"{exc.reason}"
        )
        return None


def resolve_ticket(ticket_id, device):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    url = f"{TICKET_URL}/{ticket_id}"

    payload = json.dumps(
        {
            "status": "resolved",

            "resolution":
                "Unauthorized DNS setting removed and "
                "correct DNS servers restored",

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
                f"marked resolved."
            )

            return ticket

    except urllib.error.URLError as exc:
        print(
            f"[WARN] Cannot update ticket "
            f"#{ticket_id}: {exc.reason}"
        )
        return None


def main():
    devices = get_server_devices()
    tickets = get_tickets()

    print("=" * 70)
    print("NETWORK AND DNS MONITOR")
    print("=" * 70)

    for device in devices:
        name = device["Device Name"]
        ip = device["Device Address"]

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        print()
        print("=" * 70)
        print(f"DEVICE: {name} ({ip})")
        print("=" * 70)

        # --------------------------------------------------
        # CHECK DEVICE AVAILABILITY
        # --------------------------------------------------

        online = availability.ping_device(ip)

        if not online:
            print(
                f"[OFFLINE] {name} ({ip})"
            )

            subject, body = availability.build_email(
                device,
                timestamp,
            )

            availability.send_email(
                subject,
                body,
            )

            continue

        print(
            f"[ONLINE] {name} ({ip})"
        )

        # --------------------------------------------------
        # CHECK DNS
        # --------------------------------------------------

        current_dns, raw_config = (
            read_dns_configuration(device)
        )

        if current_dns is None:
            continue

        print()
        print("Current DNS Configuration:")
        print(raw_config)

        # --------------------------------------------------
        # NORMAL DNS - DO NOTHING
        # --------------------------------------------------

        if not dns_is_altered(current_dns):
            print()
            print(
                f"[OK] No unauthorized DNS detected "
                f"on {name}."
            )
            continue

        # --------------------------------------------------
        # ROGUE DNS FOUND
        # --------------------------------------------------

        print()
        print(
            f"[ALERT] Unauthorized DNS "
            f"{ROGUE_DNS} detected on {name}."
        )

        subject, body = build_dns_email(
            device,
            current_dns,
            timestamp,
        )

        send_dns_email(
            subject,
            body,
        )

        # --------------------------------------------------
        # FIND OR CREATE TICKET
        # --------------------------------------------------

        ticket = find_dns_ticket(
            tickets,
            device,
        )

        if ticket is None:
            ticket = create_dns_ticket(
                device
            )

            if ticket:
                tickets.append(ticket)

        # --------------------------------------------------
        # CORRECT DNS
        # --------------------------------------------------

        fixed = correct_dns(
            device
        )

        if not fixed:
            print(
                f"[ERROR] {name} was not fixed."
            )
            continue

        # --------------------------------------------------
        # RESOLVE TICKET AFTER SUCCESSFUL FIX
        # --------------------------------------------------

        if ticket:
            ticket_id = (
                ticket.get("ticket_id")
                or ticket.get("id")
            )

            if ticket_id is not None:
                resolve_ticket(
                    ticket_id,
                    device,
                )

    print()
    print("=" * 70)
    print("MONITORING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
