# SENTRIX AI — REST API

Base URL: `http://127.0.0.1:8000/api` · Interactive docs: `/docs` (Swagger) · `/redoc`

## Conventions

- **Auth**: if `API_KEY` is set in `backend/.env`, mutating requests
  (`POST/PUT/PATCH/DELETE`) must send `X-API-Key: <key>` (in `production`,
  reads too). Send `X-Actor: <name>` to attribute actions in the audit log
  (defaults to `anonymous-analyst`).
- **Validation errors** return `422` with `{ "detail": "Validation failed", "errors": [...] }`.
- **Pagination**: list endpoints accept `limit` & `offset` and return
  `{ items, total, limit, offset }`.
- **Real-time**: connect a WebSocket to `/ws/live` for push updates
  (`events_ingested`, `analysis_completed`, `action_reviewed`, `incident_updated`).

## Endpoint reference (50 endpoints)

### System
- `GET /api/health` — liveness + DB check.
- `GET /api/system/status` — version, environment, LLM/SOAR configuration
  (presence only), ML model state, record counts, council weights, capabilities.

### Dashboard
- `GET /api/dashboard/summary` — KPIs, severity/status breakdowns, hourly event
  volume, tactics, recent incidents & decisions, MTTR, pending approvals.

### Events (ingestion & query)
- `POST /api/events` — ingest one event (`?analyze=true` runs AI analysis on
  affected incidents). Body: `EventIngest` (normalized fields and/or `raw` + `format`).
- `POST /api/events/batch` — ingest up to 1,000 events.
- `POST /api/events/upload` — multipart upload of JSON / JSON Lines / CSV (≤5 MB,
  ≤5,000 events). `?format=windows|sysmon|syslog|firewall|edr|cloud`.
- `GET /api/events` — filter by `severity, hostname, user, event_type,
  incident_id, tactic, min_threat, q, since, exclude_baseline`.
- `GET /api/events/{id}` — one event including raw payload.

### Incidents
- `GET /api/incidents` — filter by `status, severity, category, hostname, q`;
  `sort=last_seen|risk_score|first_seen`.
- `GET /api/incidents/{id}` — full detail incl. `analysis` and notes.
- `PATCH /api/incidents/{id}` — update `status, severity, assignee, title`.
- `POST /api/incidents/{id}/notes` — add an analyst note.
- `POST /api/incidents/{id}/analyze` — (re-)run the agent pipeline (`{use_llm}`).
- `GET /api/incidents/{id}/events` — events in the incident.
- `GET /api/incidents/{id}/actions` — proposed/approved response actions.
- `GET /api/incidents/{id}/decisions` — council decision history.
- `GET /api/incidents/{id}/report?format=markdown|json` — downloadable report.

### Response actions (human approval)
- `GET /api/actions` — filter by `status, incident_id, risk_level`.
- `POST /api/actions/{id}/review` — `{decision: approve|reject, note?}`.
  High-risk approvals require `note`.
- `POST /api/actions/{id}/complete` — mark a manual/dispatched action done.

### Agents & Council
- `GET /api/agents` — agent roster, methods, council weights, run stats.
- `GET /api/agents/runs` — per-run records (filter by `agent, incident_id, status`).
- `GET /api/council/decisions` — decision history (filter by `playbook`).
- `GET /api/council/decisions/{id}` — one decision with votes & ranking.

### Threat Intel (RAG)
- `POST /api/intel/search` — `{query, top_k, synthesize}`; returns ranked docs +
  extractive answer, or grounded LLM synthesis when enabled.
- `GET /api/intel/documents` — browse the knowledge base (filter by `doc_type, q`).
- `POST /api/intel/documents` — add a custom intel document.
- `DELETE /api/intel/documents/{doc_id}` — remove one.
- `POST /api/intel/import?kind=cisa_kev|mitre_stix` — import official feeds (≤60 MB).

### Attack Graph
- `GET /api/graph/enterprise` — Internet→crown-jewels paths, graph, centrality.
- `GET /api/graph/incident/{id}` — paths from the incident's compromised hosts.

### Digital Twin
- `GET /api/twin/playbooks` — candidate response playbooks.
- `POST /api/twin/simulate` — `{entry_hostnames, playbooks?, runs?, seed}`;
  reproducible Monte Carlo outcomes per playbook.

### Risk
- `GET /api/risk/overview` — enterprise + per-asset risk.
- `GET /api/risk/trends?days=` — events/incidents by day, top techniques, risky users.

### Assets & Users
- `GET/POST /api/assets`, `GET/PUT/DELETE /api/assets/{id}`.
- `GET/POST /api/users`, `PUT/DELETE /api/users/{id}` (passwords PBKDF2-hashed).

### Audit
- `GET /api/audit` — filter by `actor, action, entity_type, since, until`.
- `GET /api/audit/export.csv` — CSV export.

### Demo (synthetic data)
- `GET /api/demo/scenarios`, `POST /api/demo/setup`, `POST /api/demo/run` (`{scenario}`),
  `POST /api/demo/reset?confirm=RESET` (disabled in production).

## Example

```bash
# Ingest a raw Windows failed-logon and analyse it
curl -X POST http://127.0.0.1:8000/api/events \
  -H 'Content-Type: application/json' -H 'X-Actor: alice' \
  -d '{"format":"windows","raw":{"EventID":4625,"Computer":"DC-01",
       "TimeCreated":"2026-11-10T02:00:00Z",
       "EventData":{"TargetUserName":"svc_sql","IpAddress":"203.0.113.9"}}}'

# Review the proposed response actions, then approve one
curl http://127.0.0.1:8000/api/actions?status=proposed
curl -X POST http://127.0.0.1:8000/api/actions/1/review -H 'Content-Type: application/json' \
  -H 'X-Actor: alice' -d '{"decision":"approve","note":"Confirmed malicious"}'
```
