"""Send events from a JSON array / JSON Lines file to SENTRIX AI.

    python scripts/send_events.py samples/sample_events.jsonl
    python scripts/send_events.py exported_security.json --format windows

Environment: SENTRIX_API (default http://127.0.0.1:8000), SENTRIX_API_KEY.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx


def load(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    ap.add_argument("--format", default=None,
                    help="treat records as raw vendor payloads of this format (windows, sysmon, syslog, firewall, edr)")
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--no-analyze", action="store_true")
    args = ap.parse_args()

    api = os.environ.get("SENTRIX_API", "http://127.0.0.1:8000").rstrip("/")
    headers = {"X-Actor": "send-events-script"}
    if os.environ.get("SENTRIX_API_KEY"):
        headers["X-API-Key"] = os.environ["SENTRIX_API_KEY"]
    records = load(args.file)
    events = [{"format": args.format, "source": "script", "raw": r} if args.format else r for r in records]
    total = {"accepted": 0, "duplicates": 0, "rejected": 0, "incidents": set()}
    for i in range(0, len(events), args.batch):
        chunk = events[i:i + args.batch]
        r = httpx.post(f"{api}/api/events/batch", json={"events": chunk, "analyze": not args.no_analyze},
                       headers=headers, timeout=300)
        r.raise_for_status()
        body = r.json()
        for k in ("accepted", "duplicates", "rejected"):
            total[k] += body[k]
        total["incidents"].update(body["incidents_touched"])
        for err in body["errors"][:5]:
            print("  rejected:", err)
    total["incidents"] = sorted(total["incidents"])
    print(total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
