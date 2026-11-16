# SENTRIX AI — Architecture

## Overview

SENTRIX AI is a FastAPI backend (Python) plus a React/TypeScript dashboard. The
backend is organised as a layered pipeline from raw telemetry to an
explainable, human-approved response recommendation. State is held in a SQL
database (SQLite by default; any SQLAlchemy-supported URL works).

```
backend/sentrix/
├── core/         config, logging, security (API key / actor), realtime (WebSocket hub)
├── db/           SQLAlchemy engine/session + ORM models
├── schemas/      Pydantic request/response models (validation)
├── ingestion/    event normalization (vendor payloads → canonical schema)
├── detection/    rules, Oracle classifier, UEBA anomaly, scoring, correlation
├── intel/        threat-intel knowledge base + TF-IDF RAG retriever
├── graph/        networkx attack graph + path analysis
├── twin/         Monte Carlo cyber digital twin
├── risk/         enterprise/asset risk engine + trends
├── agents/       agent framework, 9 specialists, Commander orchestrator, Narrator (LLM)
├── council/      weighted-consensus decision engine
├── xai/          explainable-AI attribution
├── llm/          optional OpenAI/Anthropic client
├── response/     response actions + human-approval workflow
├── services/     ingest pipeline, audit, demo loader, report generator
└── api/          FastAPI routes (core, soc, intelligence) + dependencies
```

## Data flow

### 1. Ingestion (`ingestion/normalizer.py`, `services/ingest.py`)

An event arrives at `POST /api/events`. The normalizer converts a vendor payload
(`format` = `windows` | `sysmon` | `syslog` | `firewall` | `edr` | `cloud`) or a
pre-normalized body into a canonical `NormalizedEvent`: timestamp, host, user,
IPs, process, command line, and parser-extracted `extra` fields. A SHA-256
fingerprint de-duplicates re-sent events. Explicit fields always override parsed
ones.

The ingest service then, per event:
1. resolves the host (and source IP) to a managed `Asset` if one exists;
2. runs **behavioural anomaly** analysis;
3. runs **threat classification**;
4. fuses them into a **threat score** scaled by asset criticality;
5. persists the event;
6. **correlates** it into an incident.

Events are processed in timestamp order so baselines and correlation see history
first. A failing event never fails the batch.

### 2. Behavioural anomaly / UEBA (`detection/anomaly.py`)

Two techniques, combined with a noisy-OR (`1 - Π(1 - cᵢ)`):

- **Per-entity statistical baselines** (deterministic): time-of-day rarity, rare
  event type, new process on host, new destination, new logon source,
  failed-logon bursts and password-spray, success-after-failures, host fan-out
  (lateral movement), and event-rate spikes. Each produces an explainable
  indicator with a contribution and a human-readable detail.
- **Isolation Forest** (scikit-learn): trained on feature vectors of the stored
  event history once ≥200 events exist, cached and retrained as history grows.
  Its outlier score is one more indicator.

### 3. Classification / Oracle (`detection/rules.py`, `detection/classifier.py`)

~40 rules, each mapping observable conditions (event type, regex over
process/command-line/description, destination port, or a named extra-field
predicate such as *process opened a handle to lsass.exe*) to a MITRE ATT&CK
technique and a base score. Multiple matches combine via noisy-OR; the
highest-scoring rule sets the technique/tactic/category. Every match records the
evidence that fired it.

### 4. Scoring & correlation (`detection/scoring.py`, `detection/correlation.py`)

`threat = f(rule_base_score, anomaly, asset_criticality)`. Events above a
threshold are correlated into incidents when they share an entity (host or user,
including the resolved source host for lateral movement) within the correlation
window. Creating an incident back-fills earlier related events so the timeline
shows the full narrative. Incident aggregates (severity, risk, tactics,
techniques, hosts, users) are recomputed from its events; `incident_risk`
combines max threat, kill-chain progression and event volume, scaled by
criticality.

### 5. Multi-agent analysis (`agents/`)

The **Commander** builds an `AnalysisContext` (incident, events, assets,
candidate playbooks, attack graph) and runs nine agents in order. Each agent run
is persisted (`agent_runs`) with method, timing, confidence and output. A failing
agent is recorded and skipped.

| Agent | Method | Produces | Votes? |
|---|---|---|---|
| Observer | deterministic | entities, sources, timeline, data completeness | – |
| Behavior | ML | anomaly summary, orientation (identity vs endpoint) | ✓ |
| Oracle | deterministic | ATT&CK techniques, kill-chain stage | ✓ |
| Sentinel | deterministic | validation verdict (FP reduction) | ✓ |
| Intel | retrieval | RAG docs, KEV matches, similar past incidents (Brain) | ✓ |
| GraphAI | deterministic | attack paths to crown jewels | ✓ |
| DigitalTwin | simulation | cost/spread per response option | ✓ |
| Risk | deterministic | incident & enterprise risk | ✓ |
| Business | deterministic | business value, disruption trade-off | ✓ |

Voting agents score each candidate **response playbook** in `[0,1]`.

### 6. AI Council (`council/consensus.py`)

A confidence-weighted linear opinion pool:

```
effective_weight(a) = configured_weight(a) · confidence(a)
consensus(p)        = Σ effective_weight(a)·score_a(p) / Σ effective_weight(a)
decision            = argmax_p consensus(p)
```

*Agreement* measures how close the decision is to each agent's own preferred
option (weighted). Dissenting agents are reported, and a leave-one-out ablation
identifies pivotal agents. Contested agreement, a narrow margin, or a
likely-false-positive verdict flags the incident for human review.

### 7. Explainable AI (`xai/explainer.py`)

Deterministic, four layers: per-event detection evidence; global factor
attribution (rules vs behaviour vs progression); each agent's contribution to
the decision margin; and counterfactuals from the council ablation.

### 8. Response (`response/actions.py`)

The winning playbook's steps become `ResponseAction` rows scoped to the
incident's hosts/users/zones/external IPs. All are **proposed**. An analyst
approves or rejects each; high-risk actions require a justification note.
Approved actions dispatch to a SOAR webhook if configured, otherwise become
manual tasks with step-by-step instructions. Nothing executes automatically.

### 9. Optional LLM (`llm/client.py`, `agents/narrator.py`)

When `LLM_PROVIDER` + a key are set, the Narrator sends a *structured summary*
(never raw logs) to OpenAI or Anthropic and stores a labelled narrative under
`analysis.llm`. The RAG endpoint can likewise synthesise an answer grounded in
retrieved documents. The LLM never affects scores, votes or actions, and the
platform works fully without it.

## Real-time updates

`core/realtime.py` is a WebSocket hub (`/ws/live`). Ingestion, analysis and
approvals publish events (`events_ingested`, `analysis_completed`,
`action_reviewed`, …); the dashboard subscribes and refreshes affected views.

## Persistence model

`users`, `assets`, `incidents`, `security_events`, `incident_notes`,
`agent_runs`, `council_decisions`, `response_actions`, `audit_logs`,
`intel_documents`. SQLite runs in WAL mode with foreign keys enabled; analyses
are serialised with a process lock for write consistency.

## Frontend

React 19 + Ant Design + Recharts + @xyflow/react. A single Axios client injects
the actor/API-key headers; a `useApi` hook handles load/error/reload; a
`LiveProvider` maintains one auto-reconnecting WebSocket and lets pages refresh
on relevant live events. Pages map 1:1 to backend capabilities (Overview,
Monitoring, Incidents, Incident detail with agent/council/XAI/graph/twin tabs,
Approvals, Agents, Council, Graph, Twin, Intel, Risk, Assets, Audit, Settings).
