"""Explainable AI: transparent, deterministic explanations of every decision.

Produces four layers of explanation:
1. Detection evidence  - which rules and behavioural indicators fired, per event
2. Score attribution   - how much each factor contributed to the incident risk
3. Decision attribution- each agent's contribution to the winning margin
4. Counterfactuals     - leave-one-agent-out ablation from the council
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sentrix.agents.base import AgentOutput, AnalysisContext


def explain(ctx: AnalysisContext, council: dict[str, Any]) -> dict[str, Any]:
    events = sorted(ctx.events, key=lambda e: e.threat_score, reverse=True)
    evidence = []
    for e in events[:8]:
        cls = e.classification or {}
        an = e.anomaly_details or {}
        evidence.append({
            "event_id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "hostname": e.hostname,
            "threat_score": e.threat_score,
            "rule_evidence": [
                {"rule": i["rule"], "name": i["name"], "technique": i["technique"], "evidence": i["evidence"]}
                for i in cls.get("indicators", [])
            ],
            "behaviour_evidence": [
                {"indicator": i["indicator"], "contribution": i["contribution"], "detail": i["detail"]}
                for i in an.get("indicators", [])[:4]
            ],
        })

    # Global factor attribution: aggregate rule vs behaviour vs context weight
    rule_mass = sum((e.classification or {}).get("base_score", 0) for e in ctx.events)
    behav_mass = sum(e.anomaly_score * 100 for e in ctx.events)
    progression = 4.0 * max(0, len(ctx.incident.tactics) - 1)
    total = rule_mass + behav_mass + progression * len(ctx.events) or 1.0
    factor_attribution = [
        {"factor": "Detection rules (MITRE ATT&CK)", "share": round(rule_mass / total, 3)},
        {"factor": "Behavioural anomalies (UEBA + Isolation Forest)", "share": round(behav_mass / total, 3)},
        {"factor": "Kill-chain progression", "share": round(progression * len(ctx.events) / total, 3)},
    ]

    # Decision attribution: contribution of each agent to the decision margin
    decision = council["decision"]
    runner = council["ranking"][1]["playbook"] if len(council["ranking"]) > 1 else decision
    contributions = []
    for v in council["votes"]:
        delta = v["scores"][decision] - v["scores"][runner]
        contributions.append({
            "agent": v["agent"],
            "effective_weight": v["effective_weight"],
            "score_for_decision": v["scores"][decision],
            "score_for_runner_up": v["scores"][runner],
            "contribution_to_margin": round(v["effective_weight"] * delta, 4),
            "reason": v["reason"],
        })
    contributions.sort(key=lambda c: c["contribution_to_margin"], reverse=True)

    tactic_events: dict[str, list[int]] = defaultdict(list)
    for e in ctx.events:
        if e.mitre_tactic:
            tactic_events[e.mitre_tactic].append(e.id)

    outputs: dict[str, AgentOutput] = ctx.results
    sentinel = outputs.get("Sentinel")
    graph = outputs.get("GraphAI")
    twin = outputs.get("DigitalTwin")
    narrative = [
        f"SENTRIX classified this incident as {ctx.incident.category} with risk "
        f"{ctx.incident.risk_score:.0f}/100 based on {len(ctx.events)} correlated events.",
    ]
    if evidence and evidence[0]["rule_evidence"]:
        r = evidence[0]["rule_evidence"][0]
        narrative.append(f"The strongest signal was '{r['name']}' ({r['technique']}) on "
                         f"{evidence[0]['hostname'] or 'an unknown host'}: {r['evidence']}.")
    if sentinel:
        narrative.append(f"Sentinel validation: {sentinel.summary}")
    if graph and graph.findings.get("paths"):
        narrative.append(f"Graph AI: {graph.summary}")
    if twin and twin.findings.get("status") == "completed":
        narrative.append(f"Digital Twin: {twin.summary}")
    narrative.append(council["rationale"])
    pivotal = [a["without"] for a in council["ablation"] if a["pivotal"]]
    if pivotal:
        narrative.append(f"Pivotal agents (decision changes without them): {', '.join(pivotal)}.")

    return {
        "method": "deterministic attribution + leave-one-out ablation",
        "narrative": narrative,
        "evidence": evidence,
        "factor_attribution": factor_attribution,
        "decision_attribution": contributions,
        "counterfactuals": council["ablation"],
        "tactic_evidence": dict(tactic_events),
    }
