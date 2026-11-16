"""SENTRIX AI specialist agents.

Each agent analyses the incident from one perspective and (for voting
members) scores every candidate response playbook for the AI Council.
All agents here are deterministic/algorithmic; the only LLM-backed component
is the optional Narrator (see ``sentrix.agents.narrator``).
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from statistics import mean
from typing import Any

from sqlalchemy import select

from sentrix.agents.base import (
    METHOD_DETERMINISTIC,
    METHOD_ML,
    METHOD_RETRIEVAL,
    METHOD_SIMULATION,
    Agent,
    AgentOutput,
    AnalysisContext,
    intensity_votes,
)
from sentrix.db.models import Incident, ResponseAction
from sentrix.detection.rules import TACTIC_ORDER
from sentrix.graph import attack_graph
from sentrix.intel.knowledge import match_vulnerabilities, mitre_techniques
from sentrix.intel.rag import retriever
from sentrix.risk.risk_engine import enterprise_risk
from sentrix.twin.digital_twin import simulate

USER_INDICATORS = {"new_logon_source", "failed_logon_burst", "password_spray",
                   "success_after_failures", "host_fanout"}
HOST_INDICATORS = {"new_process", "new_destination", "event_rate_spike", "ml_outlier",
                   "first_seen_event_type"}


def _external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved)
    except ValueError:
        return False


def _norm(values: list[float]) -> list[float]:
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        return [0.5 for _ in values]
    return [(v - lo) / (hi - lo) for v in values]


class ObserverAgent(Agent):
    name = "Observer"
    role = "Event context extraction: entities, sources, timeline"
    method = METHOD_DETERMINISTIC

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        ev = ctx.events
        externals = sorted({ip for e in ev for ip in (e.src_ip, e.dst_ip) if _external(ip)})
        completeness = mean(
            (bool(e.hostname) + bool(e.user) + bool(e.process or e.src_ip or e.dst_ip)) / 3 for e in ev
        ) if ev else 0.0
        span = (ev[-1].timestamp - ev[0].timestamp).total_seconds() / 60 if ev else 0
        timeline = [
            {
                "event_id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "hostname": e.hostname,
                "user": e.user,
                "tactic": e.mitre_tactic,
                "technique": e.mitre_technique,
                "threat_score": e.threat_score,
                "severity": e.severity,
            }
            for e in ev[:100]
        ]
        unknown_hosts = sorted({e.hostname for e in ev if e.hostname and e.hostname not in ctx.assets})
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method,
            confidence=0.5 + 0.5 * completeness,
            summary=(f"{len(ev)} events over {span:.0f} min from {len({e.source for e in ev})} source(s) "
                     f"involving {len(ctx.incident.hostnames)} host(s) and {len(ctx.incident.users)} user(s)."),
            findings={
                "event_count": len(ev),
                "duration_minutes": round(span, 1),
                "sources": dict(Counter(e.source for e in ev)),
                "event_types": dict(Counter(e.event_type for e in ev).most_common(10)),
                "hosts": ctx.incident.hostnames,
                "users": ctx.incident.users,
                "external_ips": externals,
                "unmanaged_hosts": unknown_hosts,
                "data_completeness": round(completeness, 3),
                "timeline": timeline,
            },
        )


class BehaviorAgent(Agent):
    name = "Behavior"
    role = "UEBA: deviation from user and host behavioural baselines"
    method = METHOD_ML
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        scores = [e.anomaly_score for e in ctx.events]
        indicators: Counter[str] = Counter()
        examples: dict[str, str] = {}
        ready = 0
        for e in ctx.events:
            d = e.anomaly_details or {}
            b = d.get("baseline", {})
            ready += bool(b.get("user_baseline_ready") or b.get("host_baseline_ready"))
            for i in d.get("indicators", []):
                indicators[i["indicator"]] += 1
                examples.setdefault(i["indicator"], i["detail"])
        top = max(scores) if scores else 0.0
        avg = mean(scores) if scores else 0.0
        user_side = sum(c for k, c in indicators.items() if k in USER_INDICATORS)
        host_side = sum(c for k, c in indicators.items() if k in HOST_INDICATORS)
        focus = (["Authentication", "Account Compromise", "Credential Theft"] if user_side > host_side
                 else ["Malware", "Malicious Execution", "Command and Control"] if host_side else [])
        readiness = ready / len(ctx.events) if ctx.events else 0
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method,
            confidence=0.45 + 0.45 * readiness,
            summary=(f"Peak anomaly {top:.2f} (mean {avg:.2f}); "
                     + (f"dominant indicators: {', '.join(k for k, _ in indicators.most_common(3))}."
                        if indicators else "no behavioural deviations detected.")),
            findings={
                "max_anomaly": round(top, 3),
                "mean_anomaly": round(avg, 3),
                "indicator_counts": dict(indicators),
                "indicator_examples": examples,
                "baseline_readiness": round(readiness, 3),
                "orientation": "identity" if user_side > host_side else "endpoint" if host_side else "none",
            },
            votes=intensity_votes(ctx, 0.15 + 0.85 * top, focus,
                                  f"anomaly intensity {top:.2f} ({'identity' if user_side > host_side else 'endpoint'}-centric)"),
        )


class OracleAgent(Agent):
    name = "Oracle"
    role = "Threat classification against MITRE ATT&CK"
    method = METHOD_DETERMINISTIC
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        catalog = mitre_techniques()
        techniques: Counter[str] = Counter(e.mitre_technique for e in ctx.events if e.mitre_technique)
        rules = {r for e in ctx.events for r in (e.classification or {}).get("rule_ids", [])}
        tactic_idx = [TACTIC_ORDER.index(t) for t in ctx.incident.tactics if t in TACTIC_ORDER]
        stage = TACTIC_ORDER[max(tactic_idx)] if tactic_idx else None
        base = max(((e.classification or {}).get("base_score", 0) for e in ctx.events), default=0)
        cats = Counter(e.category for e in ctx.events if e.category != "Other" and e.threat_score >= 30)
        stage_boost = {"Impact": 0.25, "Exfiltration": 0.2, "Lateral Movement": 0.15,
                       "Credential Access": 0.1}.get(stage or "", 0.0)
        intensity = min(1.0, base / 100 + stage_boost)
        tech_list = [
            {
                "id": t,
                "name": catalog.get(t, {}).get("name", t),
                "tactic": catalog.get(t, {}).get("tactic"),
                "count": c,
            }
            for t, c in techniques.most_common()
        ]
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method,
            confidence=min(0.95, 0.5 + 0.08 * len(rules)),
            summary=(f"Classified as {ctx.incident.category}; {len(techniques)} ATT&CK technique(s), "
                     f"furthest kill-chain stage: {stage or 'n/a'}."),
            findings={
                "category": ctx.incident.category,
                "techniques": tech_list,
                "tactics": ctx.incident.tactics,
                "kill_chain_stage": stage,
                "kill_chain_progress": round((max(tactic_idx) + 1) / len(TACTIC_ORDER), 3) if tactic_idx else 0,
                "rules_matched": sorted(rules),
                "max_rule_score": base,
                "categories": dict(cats),
            },
            votes=intensity_votes(ctx, intensity, list(cats) or [ctx.incident.category],
                                  f"{stage or 'early'}-stage {ctx.incident.category} (rule score {base:.0f})",
                                  blend=0.45),
        )


class SentinelAgent(Agent):
    name = "Sentinel"
    role = "Threat validation and false-positive reduction"
    method = METHOD_DETERMINISTIC
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        ev = ctx.events
        rules = {r for e in ev for r in (e.classification or {}).get("rule_ids", [])}
        sources = {e.source for e in ev}
        agreement = sum(1 for e in ev if (e.classification or {}).get("base_score", 0) >= 40
                        and e.anomaly_score >= 0.25)
        strong = any((e.classification or {}).get("base_score", 0) >= 85 for e in ev)
        max_threat = max((e.threat_score for e in ev), default=0)
        evidence: list[str] = []
        doubt: list[str] = []

        v = 0.3
        if len(rules) >= 3:
            v += 0.2
            evidence.append(f"{len(rules)} independent detection rules")
        elif len(rules) == 2:
            v += 0.1
            evidence.append("2 detection rules")
        if len(sources) >= 2:
            v += 0.1
            evidence.append(f"corroborated by {len(sources)} telemetry sources")
        if agreement:
            v += min(0.2, 0.07 * agreement)
            evidence.append(f"{agreement} event(s) flagged by both rules and behaviour analytics")
        if strong:
            v += 0.2
            evidence.append("high-fidelity indicator present (rule score >= 85)")
        if len(ctx.incident.tactics) >= 3:
            v += 0.1
            evidence.append(f"kill-chain progression across {len(ctx.incident.tactics)} tactics")
        if len(ev) == 1:
            v -= 0.15
            doubt.append("single uncorroborated event")
        if set(ctx.incident.tactics) <= {"Discovery"} and ctx.incident.tactics:
            v -= 0.15
            doubt.append("discovery-only activity is common for administrators")
        if all(h not in ctx.assets for h in ctx.incident.hostnames):
            v -= 0.05
            doubt.append("hosts are not in the asset inventory")
        if max_threat < 40:
            v -= 0.1
            doubt.append("low threat scores overall")
        v = round(max(0.0, min(1.0, v)), 3)
        verdict = ("confirmed" if v >= 0.75 else "likely_malicious" if v >= 0.55
                   else "suspicious" if v >= 0.35 else "likely_false_positive")

        if verdict == "likely_false_positive":
            votes = {pid: {"score": 1.0 if pid == "PB-MONITOR" else 0.2,
                           "reason": "evidence insufficient for disruptive containment"}
                     for pid in ctx.candidate_ids}
        else:
            oracle = ctx.results.get("Oracle")
            cats = list((oracle.findings.get("categories") if oracle else {}) or {}) or [ctx.incident.category]
            votes = intensity_votes(ctx, v * max_threat / 100 + (0.1 if strong else 0), cats,
                                    f"validated as {verdict.replace('_', ' ')} (validation score {v:.2f})")
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method,
            confidence=round(0.6 + 0.35 * abs(v - 0.5) * 2, 3),
            summary=f"Verdict: {verdict.replace('_', ' ')} (validation score {v:.2f}).",
            findings={"verdict": verdict, "validation_score": v, "evidence_for": evidence,
                      "evidence_against": doubt},
            votes=votes,
        )


class IntelAgent(Agent):
    name = "Intel"
    role = "Threat-intelligence RAG and historical incident memory (Enterprise Brain)"
    method = METHOD_RETRIEVAL
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        inc = ctx.incident
        query = " ".join([inc.category, *inc.techniques, *inc.tactics,
                          *{e.event_type for e in ctx.events}])
        docs = retriever.search(ctx.db, query, top_k=8)
        playbook_hits = {d["doc_id"]: d["score"] for d in docs if d["doc_type"] == "playbook"}
        # Known-exploited vulnerabilities on involved assets
        kev = []
        for h in inc.hostnames:
            a = ctx.assets.get(h)
            if a:
                for v in match_vulnerabilities(a.software or []):
                    kev.append({"hostname": h, "cve": v["id"], "name": v["name"], "action": v["action"]})
        # Enterprise Brain: similar past incidents and the playbooks analysts approved for them
        past = ctx.db.scalars(
            select(Incident).where(Incident.id != inc.id)
            .where(Incident.status.in_(("resolved", "closed", "contained")))
            .order_by(Incident.id.desc()).limit(300)
        ).all()
        mine = set(inc.techniques)
        similar = []
        for p in past:
            theirs = set(p.techniques or [])
            union = mine | theirs
            sim = len(mine & theirs) / len(union) if union else 0
            if p.category == inc.category:
                sim = min(1.0, sim + 0.15)
            if sim >= 0.3:
                similar.append((sim, p))
        similar.sort(key=lambda x: x[0], reverse=True)
        similar = similar[:5]
        approved: Counter[str] = Counter()
        if similar:
            rows = ctx.db.scalars(
                select(ResponseAction.playbook).where(
                    ResponseAction.incident_id.in_([p.id for _, p in similar]),
                    ResponseAction.status.in_(("approved", "dispatched", "completed")),
                )
            ).all()
            approved.update(rows)
        votes = {}
        for pid in ctx.candidate_ids:
            s = 0.4 + min(0.4, playbook_hits.get(pid, 0) * 2)
            if approved:
                s += 0.3 * approved.get(pid, 0) / max(approved.values())
            reasons = []
            if pid in playbook_hits:
                reasons.append("retrieved as relevant playbook")
            if approved.get(pid):
                reasons.append(f"approved in {approved[pid]} similar past incident action(s)")
            votes[pid] = {"score": round(min(1.0, s), 4),
                          "reason": "; ".join(reasons) or "no intelligence preference"}
        top_score = docs[0]["score"] if docs else 0
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method,
            confidence=round(min(0.9, 0.35 + top_score + 0.1 * len(similar)), 3),
            summary=(f"Retrieved {len(docs)} intel documents; {len(kev)} known-exploited vulnerability "
                     f"match(es); {len(similar)} similar historical incident(s)."),
            findings={
                "query": query,
                "documents": [{k: d[k] for k in ("doc_id", "doc_type", "title", "score", "url")} for d in docs],
                "kev_matches": kev,
                "similar_incidents": [
                    {"ref": p.ref, "title": p.title, "similarity": round(s, 3), "status": p.status}
                    for s, p in similar
                ],
                "historically_approved_playbooks": dict(approved),
            },
            votes=votes,
        )


class GraphAgent(Agent):
    name = "GraphAI"
    role = "Attack-graph analysis: paths from compromised hosts to crown jewels"
    method = METHOD_DETERMINISTIC
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        res = attack_graph.analyze(ctx.db, ctx.incident.hostnames)
        graph_data = res.pop("graph")
        maxp = res.get("max_path_probability", 0.0)
        crit = res.get("critical_assets_reachable", 0)
        intensity = min(1.0, maxp * 1.4 + (0.2 if crit else 0))
        focus = ["Lateral Movement", "Ransomware"] if res.get("paths") else []
        conf = 0.85 if res["entry_points"] else 0.3
        paths = res.get("paths", [])
        summary = (f"{len(paths)} attack path(s) to high-value assets; most likely "
                   f"{' -> '.join(paths[0]['path'])} (p={paths[0]['probability']:.2f})." if paths
                   else res.get("note", "No path from compromised hosts to high-value assets."))
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method, confidence=conf, summary=summary,
            findings={**res, "graph": graph_data},
            votes=intensity_votes(ctx, intensity, focus,
                                  f"max path probability {maxp:.2f}, {crit} critical asset(s) reachable"),
        )


class DigitalTwinAgent(Agent):
    name = "DigitalTwin"
    role = "Monte Carlo simulation of attack spread under each response option"
    method = METHOD_SIMULATION
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        sim = simulate(ctx.graph, ctx.incident.hostnames, ctx.candidates, ctx.incident.users,
                       seed=ctx.incident.id)
        if sim["status"] != "completed":
            return AgentOutput(
                agent=self.name, role=self.role, method=self.method, confidence=0.2,
                summary=sim["reason"], findings=sim,
                votes={pid: {"score": 0.5, "reason": "simulation unavailable"} for pid in ctx.candidate_ids},
            )
        res = sim["results"]
        normed = _norm([r["expected_total_cost"] for r in res])
        votes = {
            r["playbook"]: {
                "score": round(1 - n, 4),
                "reason": (f"expected total cost ${r['expected_total_cost']:,.0f}; "
                           f"critical compromise p={r['critical_asset_compromise_probability']:.2f}"),
            }
            for r, n in zip(res, normed, strict=True)
        }
        best = res[0]
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method, confidence=0.85,
            summary=(f"{sim['runs']} simulations per option: {best['name']} minimises expected cost "
                     f"(${best['expected_total_cost']:,.0f}, avoids ${best['cost_avoided_vs_monitoring']:,.0f} "
                     f"vs monitoring)."),
            findings=sim, votes=votes,
        )


class RiskAgent(Agent):
    name = "Risk"
    role = "Enterprise risk assessment"
    method = METHOD_DETERMINISTIC
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        ent = enterprise_risk(ctx.db)
        involved = [a for a in ent["assets"] if a["hostname"] in ctx.incident.hostnames]
        top_asset = max((a["risk_score"] for a in involved), default=0.0)
        intensity = max(ctx.incident.risk_score, top_asset) / 100
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method, confidence=0.8,
            summary=(f"Incident risk {ctx.incident.risk_score:.0f}/100; enterprise risk {ent['score']:.0f}/100 "
                     f"({ent['level']})."),
            findings={
                "incident_risk": ctx.incident.risk_score,
                "enterprise_risk": ent["score"],
                "enterprise_level": ent["level"],
                "involved_assets": involved,
            },
            votes=intensity_votes(ctx, intensity, [], f"risk level {intensity * 100:.0f}/100", blend=0.8),
        )


class BusinessAgent(Agent):
    name = "Business"
    role = "Business impact and operational disruption analysis"
    method = METHOD_DETERMINISTIC
    votes = True

    def run(self, ctx: AnalysisContext) -> AgentOutput:
        involved = [ctx.assets[h] for h in ctx.incident.hostnames if h in ctx.assets]
        value_per_hour = sum(a.business_value_per_hour for a in involved)
        departments = sorted({a.department for a in involved})
        twin = ctx.results.get("DigitalTwin")
        sim = (twin.findings.get("results") if twin else None) or []
        votes: dict[str, dict[str, Any]] = {}
        if sim:
            disr = _norm([r["response_disruption_cost"] for r in sim])
            crit = [r["critical_asset_compromise_probability"] for r in sim]
            for r, d, c in zip(sim, disr, crit, strict=True):
                votes[r["playbook"]] = {
                    "score": round(max(0.0, 1 - 0.55 * d - 0.45 * c), 4),
                    "reason": (f"disruption ${r['response_disruption_cost']:,.0f}, "
                               f"residual critical risk {c:.2f}"),
                }
        else:
            for pb in ctx.candidates:
                votes[pb["id"]] = {"score": round(1 - 0.7 * pb["aggressiveness"], 4),
                                   "reason": "prefers least disruptive option (no simulation available)"}
        return AgentOutput(
            agent=self.name, role=self.role, method=self.method, confidence=0.7,
            summary=(f"Affected assets carry ${value_per_hour:,.0f}/h of business value across "
                     f"{', '.join(departments) or 'unknown departments'}."),
            findings={"business_value_per_hour": value_per_hour, "departments": departments,
                      "asset_count": len(involved)},
            votes=votes,
        )


PIPELINE: list[Agent] = [
    ObserverAgent(),
    BehaviorAgent(),
    OracleAgent(),
    SentinelAgent(),
    IntelAgent(),
    GraphAgent(),
    DigitalTwinAgent(),
    RiskAgent(),
    BusinessAgent(),
]
