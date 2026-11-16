"""Import official threat-intelligence feeds into a running SENTRIX AI backend.

Examples:
    # CISA Known Exploited Vulnerabilities (download then import)
    python scripts/import_intel.py cisa_kev --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    # MITRE ATT&CK Enterprise STIX bundle from a local file
    python scripts/import_intel.py mitre_stix --file enterprise-attack.json

Environment: SENTRIX_API (default http://127.0.0.1:8000), SENTRIX_API_KEY (if API_KEY is set).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=["cisa_kev", "mitre_stix"])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path)
    src.add_argument("--url")
    args = ap.parse_args()

    api = os.environ.get("SENTRIX_API", "http://127.0.0.1:8000").rstrip("/")
    headers = {"X-Actor": "intel-import-script"}
    if os.environ.get("SENTRIX_API_KEY"):
        headers["X-API-Key"] = os.environ["SENTRIX_API_KEY"]

    if args.url:
        print(f"Downloading {args.url} ...")
        r = httpx.get(args.url, timeout=120, follow_redirects=True)
        r.raise_for_status()
        data = r.content
    else:
        data = args.file.read_bytes()

    r = httpx.post(f"{api}/api/intel/import", params={"kind": args.kind}, headers=headers,
                   files={"file": ("feed.json", data, "application/json")}, timeout=300)
    if r.status_code != 200:
        print(f"Import failed: HTTP {r.status_code} {r.text[:500]}", file=sys.stderr)
        return 1
    print(r.json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
