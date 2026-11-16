"""Cyber Digital Twin: Monte Carlo attack-propagation simulation.

The twin is the enterprise attack graph (see ``sentrix.graph``) executed as an
**independent cascade** process. Starting from the compromised entry hosts,
in each time step (~1 hour of attacker dwell time) every newly compromised
node gets one chance to compromise each neighbour with the edge's
probability. Each response playbook changes the process from the step it
takes effect (``action_delay``):

* ``spread_multiplier``      - scales all edge probabilities
* ``cross_zone_multiplier``  - extra scaling for edges between network zones
* ``isolate_compromised``    - compromised hosts stop spreading
* ``egress_block``           - removes INTERNET edges and reduces exfil loss

Business impact per run = sum over compromised assets of
``business_value_per_hour * recovery_hours`` + the playbook's own disruption
cost (downtime of the assets it takes offline) + fixed response cost.

The simulation is seeded, so the same incident and inventory always produce
the same numbers. Outputs are *model estimates*, not predictions of fact.
"""

from __future__ import annotations

from typing import Any

import networkx as nx
import numpy as np

from sentrix.core.config import get_settings
from sentrix.graph.attack_graph import INTERNET

STEPS = 6
RECOVERY_HOURS = {"low": 8, "medium": 16, "high": 24, "critical": 48}
EXFIL_FACTOR = 0.15  # extra loss share for compromise when egress is open


def _zone(g: nx.DiGraph, n: str) -> str:
    return g.nodes[n].get("zone", "")


def simulate_playbook(
    g: nx.DiGraph,
    entry: list[str],
    playbook: dict[str, Any],
    users: list[str],
    runs: int,
    seed: int,
) -> dict[str, Any]:
    params = playbook["twin"]
    rng = np.random.default_rng(seed)
    nodes = [n for n in g.nodes if n != INTERNET]
    crit_nodes = {n for n in nodes if g.nodes[n].get("criticality") == "critical"}
    compromised_counts = np.zeros(runs)
    losses = np.zeros(runs)
    critical_hit = 0
    node_hits: dict[str, int] = {n: 0 for n in nodes}
    delay = int(params.get("action_delay", 1))

    for r in range(runs):
        compromised = set(entry)
        for step in range(STEPS):
            active = step >= delay
            if active and params.get("isolate_compromised"):
                break  # compromised hosts are isolated and can no longer reach neighbours
            mult = params["spread_multiplier"] if active else 1.0
            new: set[str] = set()
            # A persistent attacker retries from every foothold each step (~1h dwell).
            for u in compromised:
                for v in g.successors(u):
                    if v in compromised or v == INTERNET:
                        continue
                    # Edge probability is the chance of compromise over the whole horizon;
                    # convert it to a per-step hazard so retries do not saturate.
                    p = (1 - (1 - g.edges[u, v]["probability"]) ** (1 / STEPS)) * mult
                    if active and _zone(g, u) != _zone(g, v):
                        p *= params["cross_zone_multiplier"]
                    if rng.random() < p:
                        new.add(v)
            compromised |= new
        hits = compromised & set(nodes)
        compromised_counts[r] = len(hits)
        if hits & crit_nodes - set(entry):
            critical_hit += 1
        loss = 0.0
        for n in hits:
            node_hits[n] += 1
            crit = g.nodes[n].get("criticality", "medium")
            loss += g.nodes[n].get("business_value", 1000.0) * RECOVERY_HOURS.get(crit, 16)
        if not params.get("egress_block"):
            loss *= 1 + EXFIL_FACTOR
        losses[r] = loss

    # Disruption caused by the response itself (deterministic)
    scope = params.get("disruption_scope", "none")
    hours = float(params.get("disruption_hours", 0))
    if scope == "compromised":
        disrupted = [n for n in entry if n in g]
    elif scope == "segment":
        zones = {_zone(g, n) for n in entry if n in g}
        disrupted = [n for n in nodes if _zone(g, n) in zones]
    elif scope == "users":
        disrupted = []
    else:
        disrupted = []
    disruption = sum(g.nodes[n].get("business_value", 1000.0) * hours for n in disrupted)
    if scope == "users":
        disruption += 150.0 * hours * max(1, len(users))  # lost productivity per user-hour
    disruption += float(params.get("fixed_cost", 0))

    expected_loss = float(losses.mean())
    return {
        "playbook": playbook["id"],
        "name": playbook["name"],
        "expected_compromised": round(float(compromised_counts.mean()), 2),
        "p90_compromised": float(np.percentile(compromised_counts, 90)),
        "critical_asset_compromise_probability": round(critical_hit / runs, 3),
        "expected_breach_loss": round(expected_loss, 0),
        "p90_breach_loss": round(float(np.percentile(losses, 90)), 0),
        "response_disruption_cost": round(disruption, 0),
        "disrupted_assets": disrupted,
        "expected_total_cost": round(expected_loss + disruption, 0),
        "most_at_risk": sorted(
            ({"hostname": n, "probability": round(c / runs, 3)} for n, c in node_hits.items()
             if c and n not in entry),
            key=lambda x: x["probability"], reverse=True,
        )[:6],
    }


def simulate(
    g: nx.DiGraph,
    entry_hostnames: list[str],
    playbooks: list[dict[str, Any]],
    users: list[str] | None = None,
    runs: int | None = None,
    seed: int = 7,
) -> dict[str, Any]:
    runs = runs or get_settings().twin_simulation_runs
    entry = [h for h in entry_hostnames if h in g]
    users = users or []
    if not entry:
        return {
            "status": "skipped",
            "reason": "None of the entry hosts exist in the asset inventory.",
            "results": [],
        }
    results = [simulate_playbook(g, entry, pb, users, runs, seed) for pb in playbooks]
    baseline = next((r for r in results if r["playbook"] == "PB-MONITOR"), None)
    base_cost = baseline["expected_total_cost"] if baseline else max(r["expected_total_cost"] for r in results)
    for r in results:
        r["cost_avoided_vs_monitoring"] = round(base_cost - r["expected_total_cost"], 0)
    results.sort(key=lambda r: r["expected_total_cost"])
    return {
        "status": "completed",
        "method": "seeded Monte Carlo independent-cascade simulation",
        "runs": runs,
        "steps": STEPS,
        "seed": seed,
        "entry_points": entry,
        "results": results,
        "best_playbook": results[0]["playbook"],
    }
