# SENTRIX AI — Known Limitations & Manual Test Plan

## Scope & honest boundaries

SENTRIX AI is a **demonstrable platform and decision-support system**, not a
production SIEM/SOAR. What it genuinely does and does not do:

### Deterministic / ML / simulation — real, but bounded
- **Detection** uses ~40 curated rules and statistical + Isolation Forest
  anomaly detection. It is not a replacement for a tuned production detection
  content library; coverage is illustrative, not exhaustive.
- **Behavioural baselines** need history to be meaningful. Below
  `ANOMALY_MIN_BASELINE_EVENTS` (default 20) per entity, and below 200 events
  total for the Isolation Forest, anomaly scoring falls back to weaker signals
  and reports `baseline not ready`. The bundled demo baseline exists to make
  this observable.
- **Attack graph & digital twin** are *models*. Edge compromise probabilities
  are heuristic (exposure, KEV matches, zone, asset type), not measured. Twin
  costs are **model estimates** for comparison between response options, not
  predictions of actual loss. They are reproducible for a given seed.
- **Risk scores** are a transparent formula, not an actuarial figure.

### Threat intelligence
- The seed KB is a **curated summary** of public MITRE ATT&CK and CISA KEV
  content for offline demo use. Verify against the authoritative sources and
  refresh with `scripts/import_intel.py` (official CISA KEV JSON / MITRE STIX).
- Vulnerability matching is keyword-based over an asset's `software` list, so it
  depends on inventory quality and does not do version-range CVE matching.

### LLM
- Optional and off by default. When enabled it only writes narrative/synthesis
  and **never** changes scores, votes or actions. LLM output can still be wrong;
  it is labelled "verify before acting".

### Response
- SENTRIX **never** executes containment itself. Approved actions are either
  POSTed to a SOAR webhook you configure, or recorded as manual analyst tasks.
  Dispatch success only means the webhook accepted the request.

### Platform
- SQLite is the default; concurrent analyses are serialised with a process lock.
  For multi-worker/high-throughput use, move to Postgres and externalise the
  lock/queue.
- AuthN is a single shared API key + an actor header for attribution — enough to
  gate and audit writes, not a full RBAC/identity system.
- Ingestion is push-based (an API). The included Windows forwarder is a
  convenience script; SENTRIX does not read live OS logs itself.

## What was verified automatically

- `pytest` — 30 tests: normalization (Windows/syslog/firewall), rule
  classification → MITRE, scoring monotonicity, council weighted-consensus math,
  digital-twin reproducibility & monotonicity, attack-graph paths, the full
  approval workflow (incl. high-risk justification + audit denial record), RAG
  retrieval with LLM disabled, CISA KEV import, CSV/JSONL/raw-Windows upload,
  asset/user validation, API-key enforcement, and LLM narrative with a **mocked**
  provider plus graceful fallback on LLM failure.
- `ruff` lint clean; frontend `tsc` typecheck + production build clean; zero
  browser console errors across all pages (verified with a headless browser).
- End-to-end: all four demo scenarios ingest, correlate, analyse and produce
  council decisions + proposed actions under real `uvicorn`.

> No test result, metric, or integration in this project is fabricated. The LLM
> and SOAR integrations are exercised against **mocks** in tests because they
> require external credentials; with real credentials they use the same code path.

## Manual test plan (for your acceptance testing)

1. **Setup** — start backend + frontend (`docs/SETUP.md`). Confirm
   `GET /api/health` and the dashboard loads with "Live" connected.
2. **Demo data** — System & Demo → Load assets & baseline. Confirm 14 assets and
   ~240+ baseline events. System status should show the Isolation Forest as
   *trained*.
3. **Scenario** — run *Phishing → ransomware*. Open the incident:
   - **Overview**: timeline shows phishing → PowerShell/C2 → credential theft →
     lateral movement → backup deletion → encryption.
   - **AI Agents**: all 9 succeeded; methods labelled.
   - **AI Council**: a decision with weighted votes, dissent, ablation.
   - **Explainable AI**: narrative, factor attribution, agent margin contributions.
   - **Attack Graph**: paths from compromised hosts to DC/DB/Backup.
   - **Digital Twin**: cost table where the chosen playbook minimises expected cost.
   - **Response**: approve a low-risk action (immediate) and a high-risk action
     (requires a justification note). Reject one. Mark a manual action done.
4. **Approvals page** — confirm the actions appear and move across the
   Pending → Awaiting → Resolved views.
5. **Threat Intel** — search `T1486 ransomware` and `CVE-2021-44228`; confirm the
   right documents rank first. Toggle synthesis (shows "disabled" without a key).
6. **Attack Graph / Digital Twin pages** — run an enterprise graph and a twin
   simulation for a chosen host; re-run with the same seed → identical numbers.
7. **Risk Analytics** — confirm enterprise risk, drivers, trends and risky users.
8. **Assets** — create, edit (add `software: Log4j2 2.14.1`), and see it flagged
   as KEV-exposed in the graph/risk; delete it.
9. **Audit** — confirm every action above is recorded; export CSV.
10. **API key** — set `API_KEY` in `.env`, restart, confirm writes fail without
    the key and succeed with it (set it in System & Demo).
11. **(Optional) LLM** — set `LLM_PROVIDER` + a key, re-run analysis, confirm the
    LLM Analysis tab populates and the status shows `configured`.

## Remaining ideas (not implemented)

- Version-aware CVE matching (CPE) and live TI feed polling on a schedule.
- RBAC with per-user accounts (the users API exists; it is not yet an auth source).
- Streaming ingestion (Kafka) and a worker queue for high event rates.
- Response connectors for specific EDR/IdP/firewall vendors.
