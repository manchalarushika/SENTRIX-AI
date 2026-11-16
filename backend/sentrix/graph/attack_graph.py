"""Attack graph analysis (deterministic, networkx).

The enterprise graph is built from the asset inventory:

* nodes  - assets, plus a virtual ``INTERNET`` node
* edges  - ``connects_to`` relationships (treated as bidirectional network
  reachability) and INTERNET -> every internet-facing asset

Each directed edge carries a *compromise probability* derived from the target
asset's exposure (known-exploited vulnerabilities in its software inventory,
same network zone, internet exposure). Edge cost is ``-ln(p)`` so the
Dijkstra shortest path is the *most likely* attack path, and the path
probability is ``exp(-cost)``.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentrix.db.models import Asset
from sentrix.detection.scoring import CRITICALITY_WEIGHT
from sentrix.intel.knowledge import match_vulnerabilities

INTERNET = "INTERNET"


def edge_probability(src: dict[str, Any], dst: dict[str, Any]) -> float:
    p = 0.25
    if dst.get("vulns"):
        p += 0.25
    if src.get("zone") and src.get("zone") == dst.get("zone"):
        p += 0.1
    if src.get("id") == INTERNET:
        p = 0.2 + (0.35 if dst.get("vulns") else 0.0)
    if dst.get("asset_type") in ("domain_controller", "identity"):
        p += 0.05  # high-value identity infrastructure is a preferred target
    return round(min(0.9, p), 3)


def build_graph(db: Session) -> nx.DiGraph:
    g = nx.DiGraph()
    assets = db.scalars(select(Asset)).all()
    g.add_node(INTERNET, id=INTERNET, label="Internet", zone="external", criticality="low",
               asset_type="external", vulns=[], business_value=0.0, internet_facing=False)
    for a in assets:
        vulns = match_vulnerabilities(a.software or [])
        g.add_node(
            a.hostname,
            id=a.hostname,
            label=a.hostname,
            zone=a.network_zone,
            criticality=a.criticality,
            asset_type=a.asset_type,
            vulns=[v["id"] for v in vulns],
            business_value=a.business_value_per_hour,
            internet_facing=a.internet_facing,
            ip=a.ip_address,
            department=a.department,
            status=a.status,
            risk_score=a.risk_score,
        )
    for a in assets:
        for other in a.connects_to or []:
            if other in g and other != a.hostname:
                for u, v in ((a.hostname, other), (other, a.hostname)):
                    p = edge_probability(g.nodes[u], g.nodes[v])
                    g.add_edge(u, v, probability=p, cost=-math.log(p))
        if a.internet_facing:
            p = edge_probability(g.nodes[INTERNET], g.nodes[a.hostname])
            g.add_edge(INTERNET, a.hostname, probability=p, cost=-math.log(p))
    return g


def _paths_from(g: nx.DiGraph, sources: list[str], targets: list[str], max_paths: int = 10):
    if not sources:
        return [], {}
    h = g.copy()
    h.add_node("__SRC__")
    for s in sources:
        h.add_edge("__SRC__", s, cost=0.0, probability=1.0)
    dist, paths = nx.single_source_dijkstra(h, "__SRC__", weight="cost")
    found = []
    for t in targets:
        if t in dist and t not in sources:
            path = paths[t][1:]
            prob = math.exp(-dist[t])
            crit = g.nodes[t].get("criticality", "medium")
            found.append({
                "target": t,
                "target_criticality": crit,
                "path": path,
                "hops": len(path) - 1,
                "probability": round(prob, 4),
                "priority": round(prob * CRITICALITY_WEIGHT.get(crit, 0.5), 4),
                "techniques_enabling": sorted({v for n in path[1:] for v in g.nodes[n].get("vulns", [])}),
            })
    found.sort(key=lambda p: p["priority"], reverse=True)
    return found[:max_paths], dist


def serialize(g: nx.DiGraph, compromised: set[str] | None = None,
              highlight: set[tuple[str, str]] | None = None) -> dict[str, Any]:
    compromised = compromised or set()
    highlight = highlight or set()
    return {
        "nodes": [
            {**{k: v for k, v in d.items()}, "compromised": n in compromised}
            for n, d in g.nodes(data=True)
        ],
        "edges": [
            {"source": u, "target": v, "probability": d["probability"],
             "on_attack_path": (u, v) in highlight}
            for u, v, d in g.edges(data=True)
        ],
    }


def analyze(db: Session, entry_hostnames: list[str]) -> dict[str, Any]:
    g = build_graph(db)
    known = [h for h in entry_hostnames if h in g]
    unknown = [h for h in entry_hostnames if h not in g]
    targets = [n for n, d in g.nodes(data=True)
               if d.get("criticality") in ("high", "critical") and n != INTERNET]
    result: dict[str, Any] = {
        "method": "networkx Dijkstra over -ln(p) edge costs (deterministic)",
        "entry_points": known,
        "unmanaged_entry_points": unknown,
        "asset_count": g.number_of_nodes() - 1,
    }
    if not known:
        result.update(paths=[], choke_points=[], blast_radius=[], max_path_probability=0.0,
                      graph=serialize(g),
                      note="Incident hosts are not in the asset inventory; add them to enable path analysis.")
        return result
    paths, dist = _paths_from(g, known, targets)
    node_counts = Counter(n for p in paths for n in p["path"][1:-1])
    choke = [
        {"hostname": n, "paths_through": c, "criticality": g.nodes[n].get("criticality")}
        for n, c in node_counts.most_common(5)
    ]
    blast = sorted(
        [
            {"hostname": n, "probability": round(math.exp(-d), 4), "criticality": g.nodes[n].get("criticality")}
            for n, d in dist.items()
            if n not in ("__SRC__", INTERNET) and n not in known and math.exp(-d) >= 0.1
        ],
        key=lambda x: x["probability"],
        reverse=True,
    )
    highlight = {(p["path"][i], p["path"][i + 1]) for p in paths for i in range(len(p["path"]) - 1)}
    result.update(
        paths=paths,
        choke_points=choke,
        blast_radius=blast,
        max_path_probability=max((p["probability"] for p in paths), default=0.0),
        critical_assets_reachable=sum(1 for p in paths if p["target_criticality"] == "critical"),
        graph=serialize(g, set(known), highlight),
    )
    return result


def enterprise_exposure(db: Session) -> dict[str, Any]:
    """External attack surface: most likely paths from the Internet to crown jewels."""
    g = build_graph(db)
    targets = [n for n, d in g.nodes(data=True) if d.get("criticality") in ("high", "critical")]
    if g.out_degree(INTERNET) == 0:
        return {"paths": [], "graph": serialize(g), "note": "No internet-facing assets defined."}
    paths, _ = _paths_from(g, [INTERNET], targets)
    highlight = {(p["path"][i], p["path"][i + 1]) for p in paths for i in range(len(p["path"]) - 1)}
    return {
        "paths": paths,
        "graph": serialize(g, set(), highlight),
        "centrality": sorted(
            (
                {"hostname": n, "betweenness": round(c, 4)}
                for n, c in nx.betweenness_centrality(g, weight="cost").items()
                if n != INTERNET and c > 0
            ),
            key=lambda x: x["betweenness"],
            reverse=True,
        )[:8],
    }
