# SENTRIX AI — Feature → Implementation Map

Every required capability, where it lives, and how it is realised. The
**Type** column states honestly what kind of intelligence backs it.

| # | Feature | Type | Implementation | API / UI |
|---|---|---|---|---|
| 1 | Security event ingestion | Deterministic | `ingestion/normalizer.py` (Windows/Sysmon/syslog/firewall/EDR/cloud → canonical schema, SHA-256 dedup); `services/ingest.py` pipeline | `POST /api/events[/batch|/upload]` · Threat Monitoring |
| 2 | Behavioral anomaly detection (UEBA) | ML + deterministic | `detection/anomaly.py` — per-entity statistical baselines + scikit-learn Isolation Forest, noisy-OR fusion, explainable indicators | event `anomaly_details` · Behavior agent · Risk → risky users |
| 3 | Threat classification | Deterministic | `detection/rules.py` (~40 rules) + `detection/classifier.py`, mapped to MITRE ATT&CK | event `classification` · Oracle agent |
| 4 | Threat correlation | Deterministic | `detection/correlation.py` — time-window correlation across linked hosts/users, narrative back-fill | incidents |
| 5 | Multi-agent AI architecture | Mixed (labelled) | `agents/specialists.py` (9 agents) orchestrated by `agents/commander.py` | `GET /api/agents` · AI Agents page · incident "AI Agents" tab |
| 6 | AI Council with weighted consensus | Deterministic | `council/consensus.py` — confidence-weighted linear opinion pool, dissent, ablation | `GET /api/council/decisions` · AI Council page · council tab |
| 7 | Threat Intelligence RAG | Retrieval (+ optional LLM) | `intel/rag.py` (TF-IDF cosine) over `intel/knowledge.py` KB; optional grounded synthesis | `POST /api/intel/search` · Threat Intel page |
| 8 | Attack graph analysis | Deterministic | `graph/attack_graph.py` — networkx, Dijkstra over `-ln(p)` costs, betweenness choke points | `GET /api/graph/*` · Attack Graph page · graph tab |
| 9 | Cyber Digital Twin simulation | Simulation | `twin/digital_twin.py` — seeded Monte Carlo independent-cascade, per-playbook cost model | `POST /api/twin/simulate` · Digital Twin page · twin tab |
| 10 | Enterprise risk assessment | Deterministic | `risk/risk_engine.py` — threat×exposure×behaviour×criticality, enterprise aggregation, trends | `GET /api/risk/*` · Risk Analytics · Overview |
| 11 | Explainable AI | Deterministic | `xai/explainer.py` — evidence, factor attribution, margin contribution, counterfactuals | incident "Explainable AI" tab |
| 12 | Intelligent incident response recommendations | Deterministic + human approval | `response/actions.py` — council decision → scoped actions, approval workflow | `GET /api/actions`, `POST …/review` · Response Approvals |
| 13 | Enterprise security dashboard | — | React/antd/recharts/xyflow frontend | all pages |
| 14 | Historical incident management | Deterministic | incident lifecycle, notes, assignment, status; Intel/Brain learns from resolved incidents | Incidents · Incident detail |
| 15 | Audit logging | Deterministic | `services/audit.py` + `audit_logs` table, immutable, CSV export | `GET /api/audit` · Reports & Audit |

## Response playbook library

Seven playbooks (`backend/data/playbooks/playbooks.json`) span the response
intensity spectrum — Enhanced Monitoring, Credential Containment, Endpoint
Isolation, Network Segmentation, Ransomware Emergency Containment, Web
Application Containment, Data Exfiltration Response. Each declares its actions
(with risk levels) and the parameters the digital twin uses to model its effect.

## Demo scenarios (synthetic, alert-level)

`backend/data/scenarios/` — `ransomware`, `credential_attack`, `web_exfiltration`,
`insider_exfil`. Replayed through the real ingestion pipeline against the
fictional "Meridian Energy" inventory. All hostnames/users are invented and
external IPs use RFC 5737 documentation ranges.

## Threat-intel knowledge base

`backend/data/intel/` — curated summaries of 36 MITRE ATT&CK techniques and 9
CISA KEV vulnerabilities, plus the playbook library, seeded into
`intel_documents` on startup and indexed for RAG. Refreshable from the official
MITRE STIX bundle and CISA KEV feed via `POST /api/intel/import` or
`scripts/import_intel.py`.
