#!/usr/bin/env python3
"""Unified CLI extractor entry point — dispatches to vendor-specific modules.

Usage:
    python extract.py cisco_wlc --ip 192.168.5.99 --cred-id 1293 --model "WLC" --firmware "8.10"
    python extract.py cisco_wlc --ip 192.168.5.99 --cred-id 1293 --mode cisco_ap_shell --ap-name AP1 --firmware "8.10"
    python extract.py unifi_udm --host 192.168.5.1 --cred-id 1280

Vendor modules live in netdoc/collector/cli/ (gitignored — proprietary).
Results saved to cli-library/<vendor>/<platform>/<fw>.yaml (tracked).
"""

import importlib
import sys

_VENDORS: dict[str, str] = {
    "cisco_wlc": "netdoc.collector.cli.cisco_wlc",
    "unifi_udm": "netdoc.collector.cli.unifi_udm",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("Available vendors:")
        for v in _VENDORS:
            print(f"  {v}")
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    vendor = sys.argv[1]
    if vendor not in _VENDORS:
        print(f"Unknown vendor: {vendor!r}")
        print(f"Available: {', '.join(_VENDORS)}")
        sys.exit(1)

    # Strip vendor arg — the module's own main() uses sys.argv
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    mod = importlib.import_module(_VENDORS[vendor])
    mod.main()


if __name__ == "__main__":
    main()
