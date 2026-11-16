"""AI Council: weighted consensus over agent votes.

Each voting agent ``a`` scores every candidate playbook ``p`` in [0, 1]
(``s_a(p)``) and reports a confidence ``c_a``. The council combines them:

    effective_weight(a) = configured_weight(a) * c_a
    consensus(p)        = sum_a effective_weight(a) * s_a(p) / sum_a effective_weight(a)

The decision is ``argmax_p consensus(p)``. *Agreement* is the weighted mean of
``s_a(decision) / max_p s_a(p)`` - how close the decision is to each agent's
own preference (1.0 = every agent's first choice). *First-choice share* is the
share of effective weight whose top option equals the decision. Agents
preferring another option are reported as dissent. A leave-one-out
ablation (used by Explainable AI) shows which agents were pivotal.
"""

from __future__ import annotations

from typing import Any

from sentrix.agents.base import AgentOutput


def _consensus(votes: dict[str, AgentOutput], weights: dict[str, float],
               candidates: list[str], exclude: str | None = None) -> dict[str, float]:
    totals = dict.fromkeys(candidates, 0.0)
    wsum = 0.0
    for name, out in votes.items():
        if name == exclude or not out.votes:
            continue
        w = weights.get(name, 1.0) * out.confidence
        wsum += w
        for pid in candidates:
            totals[pid] += w * out.votes.get(pid, {}).get("score", 0.0)
    if wsum == 0:
        return dict.fromkeys(candidates, 0.0)
    return {pid: round(v / wsum, 4) for pid, v in totals.items()}


def deliberate(
    outputs: dict[str, AgentOutput],
    weights: dict[str, float],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    ids = [p["id"] for p in candidates]
    names = {p["id"]: p["name"] for p in candidates}
    voters = {n: o for n, o in outputs.items() if o.votes}
    scores = _consensus(voters, weights, ids)
    ranking = sorted(ids, key=lambda p: scores[p], reverse=True)
    decision = ranking[0]
    total_w = sum(weights.get(n, 1.0) * o.confidence for n, o in voters.items()) or 1.0

    vote_rows, dissent = [], []
    agree_w = 0.0
    support = 0.0
    for n, o in voters.items():
        assert o.votes is not None
        top = max(o.votes, key=lambda p: o.votes[p]["score"])
        eff = weights.get(n, 1.0) * o.confidence
        top_score = o.votes[top]["score"] or 1e-9
        support += eff * min(1.0, o.votes[decision]["score"] / top_score)
        if top == decision:
            agree_w += eff
        row = {
            "agent": n,
            "weight": weights.get(n, 1.0),
            "confidence": round(o.confidence, 3),
            "effective_weight": round(eff / total_w, 4),
            "preferred": top,
            "preferred_name": names[top],
            "scores": {p: o.votes[p]["score"] for p in ids},
            "reason": o.votes[top]["reason"],
        }
        vote_rows.append(row)
        if top != decision:
            dissent.append({"agent": n, "preferred": top, "preferred_name": names[top],
                            "reason": o.votes[top]["reason"]})

    agreement = round(support / total_w, 3)
    first_choice = round(agree_w / total_w, 3)
    margin = round(scores[ranking[0]] - scores[ranking[1]], 4) if len(ranking) > 1 else 1.0
    strength = "strong" if agreement >= 0.9 else "moderate" if agreement >= 0.8 else "contested"

    ablation = []
    for n in voters:
        alt = _consensus(voters, weights, ids, exclude=n)
        alt_decision = max(alt, key=alt.get)
        ablation.append({"without": n, "decision": alt_decision, "decision_name": names[alt_decision],
                         "pivotal": alt_decision != decision})

    sentinel = outputs.get("Sentinel")
    verdict = sentinel.findings.get("verdict") if sentinel else None
    human_review = strength == "contested" or verdict == "likely_false_positive" or margin < 0.02

    rationale = (
        f"The council selected '{names[decision]}' with consensus score {scores[decision]:.2f} "
        f"({strength} agreement {agreement:.0%}; first choice of {first_choice:.0%} of effective weight). "
        + (f"Runner-up '{names[ranking[1]]}' scored {scores[ranking[1]]:.2f} (margin {margin:.2f}). "
           if len(ranking) > 1 else "")
        + (f"Dissent from: {', '.join(d['agent'] for d in dissent)}. " if dissent else "No dissent. ")
        + ("Human review is recommended before acting." if human_review else "")
    ).strip()

    return {
        "method": "confidence-weighted linear opinion pool (deterministic)",
        "decision": decision,
        "decision_name": names[decision],
        "consensus_score": scores[decision],
        "agreement": agreement,
        "first_choice_share": first_choice,
        "strength": strength,
        "margin": margin,
        "human_review_recommended": human_review,
        "ranking": [{"playbook": p, "name": names[p], "score": scores[p]} for p in ranking],
        "votes": vote_rows,
        "dissent": dissent,
        "ablation": ablation,
        "weights": weights,
        "rationale": rationale,
    }
