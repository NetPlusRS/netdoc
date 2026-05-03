#!/usr/bin/env python3
"""Extract CLI command reference from UniFi Dream Machine / UDM-Pro via SSH.

Uses exec_command (no PTY/invoke_shell) — pulls mca-dump JSON + supplementary
bash commands to build a command reference YAML, then regenerates the HTML.

Usage:
    python extract_unifi.py --host 192.168.5.1 --cred-id 1280
    python extract_unifi.py --host 192.168.5.1 --user root --password SECRET
    python extract_unifi.py --host 192.168.5.1 --user root --password SECRET --dry-run
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
COMMANDS_DIR = PROJECT_ROOT / "device_commands"


def _get_cred_from_db(cred_id: int) -> tuple:
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import Credential
        from netdoc.config.credentials import decrypt
    except ImportError:
        sys.exit("Cannot import NetDoc — check that DATABASE_URL is set in .env")

    with SessionLocal() as db:
        cred = db.query(Credential).filter(Credential.id == cred_id).first()
        if not cred:
            sys.exit(f"Credential ID={cred_id} not found in DB")
        username = cred.username
        try:
            password = decrypt(cred.password_encrypted)
        except Exception:
            password = cred.password_encrypted
        return username, password


def _exec(client, cmd: str, timeout: int = 30) -> str:
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR: {e}]"


def _slugify(model: str, firmware: str) -> str:
    text = re.sub(r"[^\w\s]", " ", (model or "unknown").lower())
    text = re.sub(r"\s+", "_", text.strip())
    text = re.sub(r"_+", "_", text).strip("_")
    fw_parts = re.split(r"[.\-]", firmware or "")
    fw_short = ".".join(fw_parts[:2]) if len(fw_parts) >= 2 else (firmware or "unknown")
    slug = f"{text}_{fw_short}"
    return re.sub(r"_+", "_", slug).strip("_")


def _discover_binaries(client) -> list:
    out = _exec(client, "ls /usr/bin/mca-* /usr/bin/ubnt-* 2>/dev/null")
    bins = []
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith("[ERROR"):
            bins.append(Path(line).name)
    return sorted(set(bins))


def _known_commands() -> dict:
    return {
        "mca-dump": {
            "_desc": (
                "Full device state dump — primary data source. Returns large JSON with: "
                "hostname, model, firmware, if_table (WAN/LAN interfaces), "
                "port_table (physical switch ports + mac_table per port), "
                "network_table (VLANs/subnets), lldp_table, dpi_stats, connections."
            ),
            "_tags": ["status", "json", "primary", "interfaces", "neighbors", "clients"],
        },
        "mca-cli-op": {
            "_desc": "MCA CLI one-shot operations (no interactive shell needed).",
            "_tags": ["status"],
            "info": {
                "_desc": (
                    "Quick device summary: model, firmware version, MAC, IP, "
                    "uptime, NTP status, inform URL."
                ),
                "_tags": ["status", "identity"],
            },
        },
        "mca-cli": {
            "_desc": (
                "Interactive UniFi CLI shell — management only (4 commands). "
                "NOT useful for data extraction. Prompt: 'UniFi# '"
            ),
            "_tags": ["management"],
            "info": {
                "_desc": "Display device information.",
                "_tags": ["status", "identity"],
            },
            "reboot": {
                "_desc": "Reboot the device.",
                "_tags": ["management", "dangerous"],
            },
            "set-default": {
                "_desc": "Restore device to factory default settings.",
                "_tags": ["management", "dangerous"],
            },
            "upgrade": {
                "_desc": "Upgrade firmware: upgrade <firmware_url>",
                "_tags": ["management"],
            },
        },
        "mca-sta": {
            "_desc": (
                "Client station statistics (JSON). "
                "May return malformed JSON on some firmware versions (FW 5.0.16 affected)."
            ),
            "_tags": ["clients", "wifi", "json"],
        },
        "mca-scan": {
            "_desc": "WLAN site survey / scan results.",
            "_tags": ["wifi"],
        },
        "mca-monitor": {
            "_desc": "Live monitoring data stream.",
            "_tags": ["status", "monitoring"],
        },
        "lldpctl": {
            "_desc": (
                "LLDP neighbor table — formatted text. "
                "Shows: neighbor chassis ID, system name, system description, local port, "
                "remote port, management IP, VLAN. "
                "UDM-Pro typically finds 2-4 neighbors."
            ),
            "_tags": ["lldp", "neighbors", "topology"],
        },
        "ubnt-device-info": {
            "_desc": "Hardware identity and model information (Ubiquiti proprietary).",
            "_tags": ["identity"],
            "summary": {
                "_desc": "Display device family, model name, MAC address, firmware version.",
                "_tags": ["status", "identity"],
            },
        },
        "ubnt-systool": {
            "_desc": "System management tool (Ubiquiti proprietary).",
            "_tags": ["management", "system"],
        },
        "ubnt-ipcalc": {
            "_desc": "IP address calculation utility.",
            "_tags": ["networking"],
        },
        "ubnt-make-support-file": {
            "_desc": "Generate a support bundle archive for Ubiquiti TAC submission.",
            "_tags": ["management", "diagnostics"],
        },
        "ubios-udapi-client": {
            "_desc": (
                "Internal UDAPI socket client. "
                "Connects to /var/run/ubnt-udapi-server.sock. "
                "REST-style paths — mostly 404 on FW 5.0.x without known valid routes."
            ),
            "_tags": ["internal", "api"],
        },
        "ip": {
            "_desc": "Linux network configuration and monitoring (iproute2).",
            "_tags": ["networking"],
            "addr": {
                "_desc": "Show interface IP addresses (detailed).",
                "_tags": ["interfaces", "networking"],
                "show": {
                    "_desc": "Display IP addresses for all or a specific interface.",
                    "_tags": ["interfaces"],
                },
            },
            "route": {
                "_desc": "Show or modify routing table.",
                "_tags": ["routing"],
                "show": {
                    "_desc": "Display current IPv4 routing table.",
                    "_tags": ["routing"],
                },
            },
            "neigh": {
                "_desc": "Show ARP/IPv6 neighbor cache.",
                "_tags": ["arp", "neighbors"],
                "show": {
                    "_desc": "Display ARP neighbor table with state (REACHABLE/STALE/FAILED).",
                    "_tags": ["arp"],
                },
            },
            "link": {
                "_desc": "Show interface link-layer information.",
                "_tags": ["interfaces"],
            },
            "-br": {
                "_desc": "Brief output modifier (combine with addr/link/route for compact view).",
                "_tags": ["interfaces"],
                "addr": {
                    "_desc": "Interface addresses in brief one-line format.",
                    "_tags": ["interfaces"],
                },
                "link": {
                    "_desc": "Interface link status in brief one-line format.",
                    "_tags": ["interfaces"],
                },
            },
        },
        "ss": {
            "_desc": "Socket statistics — replacement for netstat (faster, more features).",
            "_tags": ["networking", "security"],
            "-tulpn": {
                "_desc": "TCP and UDP listening ports with PID/process names (no DNS lookup).",
                "_tags": ["networking", "security"],
            },
            "-s": {
                "_desc": "Summary statistics for all socket types.",
                "_tags": ["networking", "status"],
            },
        },
        "arp": {
            "_desc": "ARP cache (legacy — prefer 'ip neigh show' for richer output).",
            "_tags": ["arp", "neighbors"],
            "-a": {
                "_desc": "Display ARP cache in BSD format.",
                "_tags": ["arp"],
            },
            "-n": {
                "_desc": "Display numeric addresses (skip reverse DNS lookups).",
                "_tags": ["arp"],
            },
        },
        "cat /proc/meminfo": {
            "_desc": "Memory usage details (total, free, available, cached, swap).",
            "_tags": ["system", "status"],
        },
        "cat /proc/loadavg": {
            "_desc": "System load averages: 1min / 5min / 15min, running/total processes, last PID.",
            "_tags": ["system", "status"],
        },
        "uname -a": {
            "_desc": "Full kernel version string and architecture (Linux aarch64).",
            "_tags": ["system", "identity"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract UniFi UDM-Pro CLI reference and regenerate HTML."
    )
    parser.add_argument("--host", default="192.168.5.1", help="Device IP (default: 192.168.5.1)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--cred-id", type=int, help="NetDoc DB credential ID")
    parser.add_argument("--user", help="SSH username (alternative to --cred-id)")
    parser.add_argument("--password", help="SSH password (alternative to --cred-id)")
    parser.add_argument("--timeout", type=int, default=15, help="SSH connect timeout in seconds")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build YAML from known commands without SSH connection",
    )
    args = parser.parse_args()

    if args.dry_run:
        print("[*] Dry-run mode — skipping SSH, using known commands only.")
        hostname = "unknown"
        model = "UniFi Dream Machine Pro"
        firmware = "unknown"
        system = "UniFiOS Debian 11 aarch64"
        extra_bins = []
    else:
        if args.cred_id:
            username, password = _get_cred_from_db(args.cred_id)
        elif args.user and args.password:
            username, password = args.user, args.password
        else:
            parser.error("Provide --cred-id OR both --user and --password (or --dry-run)")

        try:
            import paramiko
        except ImportError:
            sys.exit("paramiko not installed — run: pip install paramiko")

        print(f"[*] Connecting to {args.host}:{args.port} as {username}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            args.host,
            port=args.port,
            username=username,
            password=password,
            timeout=args.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        print("[+] Connected.")

        print("[*] Reading device identity via mca-dump...")
        mca_raw = _exec(client, "mca-dump 2>/dev/null", timeout=30)
        mca = {}
        try:
            mca = json.loads(mca_raw)
        except json.JSONDecodeError:
            print("[!] mca-dump returned non-JSON — falling back to ubnt-device-info.")

        hostname = mca.get("hostname") or "unknown"
        model = mca.get("model_display") or mca.get("model") or ""
        firmware = mca.get("version") or ""
        arch = mca.get("architecture") or "unknown"

        if not model or not firmware:
            info_out = _exec(client, "ubnt-device-info summary 2>/dev/null")
            for line in info_out.splitlines():
                if "Model:" in line and not model:
                    model = line.split(":", 1)[1].strip()
                if "Firmware:" in line and not firmware:
                    firmware = line.split(":", 1)[1].strip()

        model = model or "UniFi Device"
        firmware = firmware or "unknown"
        system = f"UniFiOS Debian 11 {arch}"
        print(f"[+] Device: {hostname}  model={model}  fw={firmware}  arch={arch}")

        print("[*] Discovering mca-*/ubnt-* binaries...")
        extra_bins = _discover_binaries(client)
        if extra_bins:
            print(f"[+] Found: {', '.join(extra_bins)}")
        else:
            print("[+] No extra binaries found.")

        client.close()
        print("[+] SSH session closed.")

    slug = _slugify(model, firmware)
    print(f"[*] Slug: {slug}")

    known = _known_commands()
    commands = dict(known)
    for b in extra_bins:
        if b not in commands:
            commands[b] = {
                "_desc": f"Discovered binary — run '{b} --help 2>&1' for usage.",
                "_tags": ["discovered"],
            }

    doc = {
        "model": model,
        "firmware": firmware,
        "system": system,
        "source_ip": args.host,
        "notes": (
            f"Device: {hostname} ({args.host}). "
            "Extracted via SSH exec_command (no PTY). "
            f"Primary data source: mca-dump JSON. Shell: /bin/bash ({system})."
        ),
        "commands": commands,
    }

    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML not installed — run: pip install pyyaml")

    COMMANDS_DIR.mkdir(exist_ok=True)
    out_path = COMMANDS_DIR / f"{slug}.yaml"
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"[+] Saved: {out_path}")

    print("[*] Regenerating CLI reference HTML...")
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "export_cli_reference.py")],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("[+] HTML regenerated: device_commands/cli_reference.html")
    else:
        print(f"[!] HTML generation failed:\n{result.stderr}")


if __name__ == "__main__":
    main()
