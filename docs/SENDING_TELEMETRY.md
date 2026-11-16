# Sending Telemetry to SENTRIX AI

SENTRIX AI ingests events through its API. Any source that can POST JSON can feed
it. Set `SENTRIX_API` (default `http://127.0.0.1:8000`) and, if `API_KEY` is set,
`SENTRIX_API_KEY` for the helper scripts.

## 1. Normalized events (simplest)

Send canonical fields directly:

```bash
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' -H 'X-Actor: forwarder' \
  -d '{"event_type":"Failed Logon","hostname":"DC-01","user":"svc_sql",
       "src_ip":"203.0.113.9","source":"ad"}'
```

## 2. Raw vendor payloads

Provide the vendor record in `raw` and a `format`; the normalizer extracts the
fields. Supported formats: `windows`, `sysmon`, `syslog`, `firewall`, `edr`,
`cloud`.

```bash
# Windows Security event
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' \
  -d '{"format":"windows","raw":{"EventID":4688,"Computer":"WS-01",
       "EventData":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe",
       "CommandLine":"cmd /c whoami"}}}'

# Linux syslog line
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' \
  -d '{"format":"syslog","raw":{"message":"Nov 10 02:01 web-01 sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2"}}'
```

## 3. Bulk upload (file)

`POST /api/events/upload` accepts a JSON array, JSON Lines, or CSV file
(≤5 MB, ≤5,000 events). See `backend/samples/sample_events.jsonl` and
`sample_firewall.csv`.

```bash
python backend/scripts/send_events.py backend/samples/sample_events.jsonl
python backend/scripts/send_events.py exported_windows.json --format windows
```

## 4. Windows Event Log forwarder (PowerShell)

`backend/scripts/forward_windows_events.ps1` reads recent events with
`Get-WinEvent` (read-only) and forwards them. Run **as Administrator** to read
the Security log.

```powershell
$env:SENTRIX_API = "http://sentrix-host:8000"
.\forward_windows_events.ps1 -Minutes 60
.\forward_windows_events.ps1 -LogName "Microsoft-Windows-Sysmon/Operational" -Format sysmon
```

Schedule it with Task Scheduler for continuous forwarding.

## Notes

- Events are **de-duplicated** by content fingerprint, so re-sending the same
  window is safe.
- `?analyze=true` (default on single/batch ingest) runs AI analysis on any
  incident the events touch. Set `analyze=false` for high-rate bulk loads and
  analyse later via `POST /api/incidents/{id}/analyze`.
- Define your assets (hostnames, zones, `connects_to`, `software`) so the attack
  graph, digital twin and KEV matching are meaningful.

## Refreshing threat intelligence

```bash
# CISA Known Exploited Vulnerabilities (official JSON feed)
python backend/scripts/import_intel.py cisa_kev \
  --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# MITRE ATT&CK Enterprise STIX bundle (local file)
python backend/scripts/import_intel.py mitre_stix --file enterprise-attack.json
```
